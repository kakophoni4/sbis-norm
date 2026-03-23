"""
Заполнить КПП (и при необходимости Organization) из отправленных документов СБИС.

Два режима:
  1) --from-sbis: через СБИС.СписокДокументов с фильтром по году/датам (как send_nds_extra),
     достаёт вложения (XML), парсит СвНП/НПЮЛ → КПП.
  2) По умолчанию: сканирует Document в БД, открывает локальные файлы (Document.files).

Примеры:
  .venv/bin/python3 manage.py sync_kpp_from_documents --from-sbis --year 2025 --dry-run
  .venv/bin/python3 manage.py sync_kpp_from_documents --from-sbis --date-from 01.01.2025 --date-to 31.12.2025
  .venv/bin/python3 manage.py sync_kpp_from_documents --sync-certificates  # локальные файлы
"""
import base64
import json
import os
import tempfile
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import close_old_connections, transaction

from reports.models import Certificate, Document, Organization
from reports.sbis_service import (
    CertInvalidNoRetryError,
    auth_sbis_by_cert,
    export_cert_der,
    get_thumbprint_from_cert,
    sbis_rpc,
)

try:
    from reports.sbis_service import extract_our_org_from_nds_xml
except ImportError:
    extract_our_org_from_nds_xml = None


def _extract_our_org_from_nds_xml(xml_path: str) -> dict | None:
    """
    Из отчёта НДС (XML) достать нашу организацию: СвНП/НПЮЛ → ИНН, КПП, название.
    Локальная копия на случай, если в sbis_service.py ещё нет extract_our_org_from_nds_xml.
    """
    if not xml_path or not os.path.isfile(xml_path):
        return None
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        doc = root.find("Документ")
        if doc is None:
            return None
        np = doc.find("СвНП/НПЮЛ")
        if np is None:
            return None
        inn = (np.attrib.get("ИННЮЛ") or "").strip()
        kpp = (np.attrib.get("КПП") or "").strip()
        name = (np.attrib.get("НаимОрг") or "").strip()
        if not inn or not kpp or len(kpp) != 9 or not kpp.isdigit():
            return None
        return {"inn": inn, "kpp": kpp, "name": name or f"ИНН {inn}"}
    except Exception:
        return None


def _get_extract_our_org():
    """Использовать sbis_service или локальную реализацию."""
    return extract_our_org_from_nds_xml or _extract_our_org_from_nds_xml


def _process_one_inn_sbis(
    inn: str,
    csptest_name: str,
    date_from_str: str,
    date_to_str: str,
) -> tuple[str, tuple[str, str] | None, bool, str]:
    """
    Обработать один ИНН: авторизация → СписокДокументов → извлечь КПП из JSON.
    Возвращает (inn, (kpp, name) или None, delete_cert, short_message).
    """
    try:
        return _process_one_inn_sbis_impl(inn, csptest_name, date_from_str, date_to_str)
    finally:
        close_old_connections()


def _process_one_inn_sbis_impl(
    inn: str,
    csptest_name: str,
    date_from_str: str,
    date_to_str: str,
) -> tuple[str, tuple[str, str] | None, bool, str]:
    cert_path = f"/tmp/sbis_kpp_docs_{inn}.cer"
    try:
        try:
            export_cert_der(csptest_name, cert_path)
            thumbprint = get_thumbprint_from_cert(cert_path)
            session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
        except CertInvalidNoRetryError:
            cert = Certificate.objects.filter(inn=inn, has_private_key=True, csptest_name=csptest_name).first()
            if cert:
                try:
                    cert.delete()
                except Exception:
                    pass
            return (inn, None, False, "сертификат отозван/просрочен — удалён из БД")
        except Exception as e:
            err_msg = str(e)
            if _is_revoked_or_untrusted_cert_error(err_msg):
                cert = Certificate.objects.filter(inn=inn, has_private_key=True, csptest_name=csptest_name).first()
                if cert:
                    try:
                        cert.delete()
                    except Exception:
                        pass
                return (inn, None, False, "сертификат отозван/просрочен — удалён из БД")
            return (inn, None, False, f"ошибка авторизации: {(str(e))[:80]}")

        try:
            data = sbis_rpc(
                inn=inn,
                session_id=session_id,
                method="СБИС.СписокДокументов",
                params={
                    "Фильтр": {
                        "Тип": "ОтчетФНС",
                        "Направление": "Исходящий",
                        "ДатаС": date_from_str,
                        "ДатаПо": date_to_str,
                        "Навигация": {"РазмерСтраницы": "50"},
                    }
                },
                timeout=45,
            )
        except Exception as e:
            return (inn, None, False, f"ошибка СписокДокументов: {(str(e))[:80]}")

        if data.get("error"):
            return (inn, None, False, f"ответ с ошибкой: {(str(data['error']))[:80]}")

        result = data.get("result") or {}
        docs = result.get("Документ") or []
        if not isinstance(docs, list):
            return (inn, None, False, "документов: 0")

        # КПП из result.Организация
        top_org = result.get("Организация") or {}
        top_svul = top_org.get("СвЮЛ") or result.get("СвЮЛ") or {}
        top_inn = (top_org.get("ИНН") or top_svul.get("ИНН") or "").strip()
        top_kpp = (top_org.get("КПП") or top_svul.get("КПП") or result.get("КПП") or "").strip()
        if top_inn == inn and top_kpp and len(top_kpp) == 9 and top_kpp.isdigit():
            name = (top_org.get("Наименование") or top_svul.get("НаимОрг") or f"ИНН {inn}")[:255]
            return (inn, (top_kpp, name), False, f"КПП: {top_kpp}")

        # КПП из полей документов (НашаОрганизация.СвЮЛ)
        for doc in docs:
            res = _kpp_inn_from_doc_json(doc, inn)
            if res:
                kpp, name_org = res
                return (inn, (kpp, name_org[:255]), False, f"КПП: {kpp}")

        return (inn, None, False, f"документов: {len(docs)}, КПП не найден")
    finally:
        try:
            if os.path.isfile(cert_path):
                os.remove(cert_path)
        except OSError:
            pass


def _kpp_inn_from_doc_json(doc: dict, our_inn: str) -> tuple[str, str] | None:
    """
    Попытаться достать КПП и имя организации из JSON документа СБИС (без разбора XML).
    В ответе СписокДокументов: НашаОрганизация.СвЮЛ (ИНН, КПП, НаимОрг).
    Возвращает (kpp, name) если ИНН совпадает с our_inn, иначе None.
    """
    if not doc:
        return None
    # НашаОрганизация — наша компания в документе (СБИС отдаёт СвЮЛ с ИНН/КПП)
    our_org = doc.get("НашаОрганизация") or doc.get("Организация") or {}
    svul = our_org.get("СвЮЛ") or doc.get("СвЮЛ") or {}
    doc_inn = (our_org.get("ИНН") or svul.get("ИНН") or doc.get("ИНН") or "").strip()
    if doc_inn != our_inn:
        return None
    kpp = (our_org.get("КПП") or svul.get("КПП") or doc.get("КПП") or "").strip()
    name = (our_org.get("Наименование") or our_org.get("НаимОрг") or svul.get("НаимОрг") or doc.get("Наименование") or "").strip()
    if not kpp or len(kpp) != 9 or not kpp.isdigit():
        return None
    return (kpp, name or f"ИНН {our_inn}")


def _is_revoked_or_untrusted_cert_error(message: str) -> bool:
    """Сообщение СБИС: сертификат отозван, просрочен или не доверенный — удалить из БД."""
    if not message:
        return False
    msg = message.lower()
    return (
        "отозван" in msg
        or "не является доверенным" in msg
        or "выберите другой сертификат" in msg
        or "просроченному сертификату" in msg
        or "аутентификация по просроченному" in msg
        or "certificate invalid (no retry)" in msg
        or "certificate revoked/untrusted" in msg
    )


class Command(BaseCommand):
    help = "Взять КПП из XML отправленных документов (СвНП/НПЮЛ) и записать в БД"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Только показать, что бы обновили",
        )
        parser.add_argument(
            "--status",
            dest="statuses",
            action="append",
            default=[],
            help="(локальные файлы) Статусы документов. По умолчанию: SENT, CONFIRMED, UPLOADED",
        )
        parser.add_argument(
            "--sync-certificates",
            action="store_true",
            help="Обновить Certificate.kpp для совпадающего ИНН",
        )
        parser.add_argument(
            "--ensure-organization",
            action="store_true",
            help="Создать Organization, если нет (имя из XML)",
        )
        parser.add_argument(
            "--from-sbis",
            action="store_true",
            help="Использовать СБИС.СписокДокументов (как send_nds_extra) вместо локальных файлов",
        )
        parser.add_argument(
            "--year",
            type=int,
            help="Год для фильтра СБИС (например 2025). Или --date-from/--date-to",
        )
        parser.add_argument(
            "--date-from",
            dest="date_from",
            default="",
            help="Дата начала периода (ДД.ММ.ГГГГ) для --from-sbis",
        )
        parser.add_argument(
            "--date-to",
            dest="date_to",
            default="",
            help="Дата конца периода (ДД.ММ.ГГГГ) для --from-sbis",
        )
        parser.add_argument(
            "--year-from-today",
            action="store_true",
            help="Период: последний год до сегодня (текущая дата − 365 дней — текущая дата)",
        )
        parser.add_argument(
            "--inn",
            dest="inn_filter",
            default="",
            help="Обработать только этот ИНН (для проверки, например --inn 9729337785)",
        )
        parser.add_argument(
            "--dump-response",
            action="store_true",
            help="Вывести сырой ответ СБИС.СписокДокументов (структура и первый документ) и выйти",
        )
        parser.add_argument(
            "--workers",
            type=int,
            default=1,
            metavar="N",
            help="Параллельных потоков для --from-sbis (по умолчанию 1). При большом числе может потребоваться ulimit -n",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Запрашивать СБИС даже для ИНН, у которых в Organization уже есть КПП",
        )

    def handle(self, *args, **options):
        dry = options["dry_run"]
        sync_certs = options["sync_certificates"]
        ensure_org = options["ensure_organization"]
        from_sbis = options["from_sbis"]

        if from_sbis:
            inn_to_data = self._collect_from_sbis(options)
        else:
            inn_to_data = self._collect_from_local_files(options)

        if not inn_to_data:
            self.stdout.write(self.style.WARNING("Нечего обновлять."))
            return

        self._update_organizations(inn_to_data, dry, sync_certs, ensure_org)

    def _collect_from_sbis(self, options) -> dict[str, tuple[str, str]]:
        """СБИС.СписокДокументов → вложения → XML → КПП."""
        from datetime import datetime, timedelta

        year = options.get("year")
        date_from_str = (options.get("date_from") or "").strip()
        date_to_str = (options.get("date_to") or "").strip()
        year_from_today = options.get("year_from_today")

        if year_from_today:
            today = datetime.now()
            date_from_str = (today - timedelta(days=365)).strftime("%d.%m.%Y")
            date_to_str = today.strftime("%d.%m.%Y")
        elif year:
            date_from_str = f"01.01.{year}"
            date_to_str = f"31.12.{year}"
        elif not date_from_str or not date_to_str:
            today = datetime.now()
            date_from_str = (today - timedelta(days=365)).strftime("%d.%m.%Y")
            date_to_str = today.strftime("%d.%m.%Y")

        self.stdout.write(f"Запрос СБИС.СписокДокументов: {date_from_str} — {date_to_str}")
        self.stdout.flush()

        self.stdout.write("Получение списка ИНН из БД...")
        self.stdout.flush()
        inns = list(Certificate.objects.exclude(inn__isnull=True).exclude(inn="").values_list("inn", flat=True).distinct())
        inn_filter = (options.get("inn_filter") or "").strip()
        if inn_filter:
            if inn_filter not in inns:
                self.stdout.write(self.style.WARNING(f"ИНН {inn_filter} не найден в Certificate (или нет записей с этим ИНН)"))
                return {}
            inns = [inn_filter]
        if not inns:
            self.stdout.write(self.style.WARNING("Нет ИНН в Certificate для запроса СБИС"))
            return {}

        workers = max(1, int(options.get("workers") or 1))
        dump_response = options.get("dump_response")
        force = options.get("force")

        # Список (inn, csptest_name) для обработки
        cert_map = {}
        for inn, csp in Certificate.objects.filter(
            has_private_key=True
        ).exclude(csptest_name__isnull=True).exclude(inn__isnull=True).exclude(inn="").values_list("inn", "csptest_name"):
            if inn in inns and inn not in cert_map:
                cert_map[inn] = csp
        candidate_inns = [inn for inn in sorted(set(inns)) if inn in cert_map]

        # Пропуск ИНН, у которых в Organization уже есть валидный КПП (если не --force)
        if not force:
            existing_kpp_inns = set()
            for row in Organization.objects.filter(inn__in=candidate_inns).exclude(kpp__isnull=True).exclude(kpp="").values_list("inn", "kpp"):
                inn, kpp = row
                if kpp and len(str(kpp).strip()) == 9 and str(kpp).strip().isdigit():
                    existing_kpp_inns.add(inn)
            candidate_inns = [inn for inn in candidate_inns if inn not in existing_kpp_inns]
            if existing_kpp_inns:
                self.stdout.write(f"Пропуск {len(existing_kpp_inns)} ИНН с уже заполненным КПП в Organization (используйте --force для повторного запроса)")

        tasks = [(inn, cert_map[inn]) for inn in candidate_inns]
        total_inns = len(tasks)
        if not tasks:
            self.stdout.write(self.style.WARNING("Нет ИНН с сертификатом (has_private_key, csptest_name) для запроса СБИС"))
            return {}
        self.stdout.write(
            f"ИНН к обработке: {total_inns}"
            + (f" (только {inn_filter})" if inn_filter else "")
            + (f", потоков: {workers}" if workers > 1 else "")
        )

        inn_to_data: dict[str, tuple[str, str]] = {}

        if workers <= 1 or dump_response:
            # Последовательно (с подробным выводом или при dump_response)
            for idx, (inn, csptest_name) in enumerate(tasks, 1):
                self.stdout.write(f"[{idx}/{total_inns}] ИНН {inn}...")
                if dump_response and idx == 1:
                    cert_path = f"/tmp/sbis_kpp_docs_{inn}.cer"
                    export_cert_der(csptest_name, cert_path)
                    thumbprint = get_thumbprint_from_cert(cert_path)
                    session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
                    data = sbis_rpc(
                        inn=inn, session_id=session_id,
                        method="СБИС.СписокДокументов",
                        params={
                            "Фильтр": {
                                "Тип": "ОтчетФНС", "Направление": "Исходящий",
                                "ДатаС": date_from_str, "ДатаПо": date_to_str,
                                "Навигация": {"РазмерСтраницы": "50"},
                            }
                        },
                        timeout=45,
                    )
                    self._dump_sbis_list_response(data, inn)
                    return {}
                res_inn, result, _del, msg = _process_one_inn_sbis(inn, csptest_name, date_from_str, date_to_str)
                if result:
                    inn_to_data[res_inn] = result
                    self.stdout.write(f"  {msg}")
                else:
                    if "удалён из БД" in msg:
                        self.stdout.write(self.style.ERROR(f"  {msg}"))
                    else:
                        self.stdout.write(self.style.WARNING(f"  {msg}"))
        else:
            # Параллельно
            lock = threading.Lock()
            done = [0]  # mutable to update in closure

            def _collect(r):
                nonlocal done
                res_inn, result, _del, msg = r
                with lock:
                    done[0] += 1
                    if result:
                        inn_to_data[res_inn] = result
                        self.stdout.write(f"[{done[0]}/{total_inns}] ИНН {res_inn}: {msg}")
                    else:
                        st = self.style.ERROR if "удалён из БД" in msg else self.style.WARNING
                        self.stdout.write(st(f"[{done[0]}/{total_inns}] ИНН {res_inn}: {msg}"))

            with ThreadPoolExecutor(max_workers=workers) as pool:
                futs = [
                    pool.submit(_process_one_inn_sbis, inn, csp, date_from_str, date_to_str)
                    for inn, csp in tasks
                ]
                for fut in as_completed(futs):
                    try:
                        _collect(fut.result())
                    except Exception as e:
                        with lock:
                            done[0] += 1
                            self.stdout.write(self.style.WARNING(f"[{done[0]}/{total_inns}] ошибка: {e}"))

        self.stdout.write(f"Найдено уникальных ИНН с КПП из СБИС: {len(inn_to_data)}")
        return inn_to_data

    def _dump_sbis_list_response(self, data: dict, inn: str) -> None:
        """Вывести структуру ответа СБИС.СписокДокументов (для отладки)."""
        def _short(v, max_len=120):
            if v is None:
                return "null"
            if isinstance(v, (str, bytes)):
                s = v if isinstance(v, str) else v.decode("utf-8", errors="replace")
                if len(s) > max_len:
                    return repr(s[:max_len]) + f" ... ({len(s)} символов)"
                return repr(s)
            if isinstance(v, dict):
                return "{" + ", ".join(sorted(v.keys())) + "}"
            if isinstance(v, list):
                return f"[{len(v)} элементов]"
            return repr(v)

        result = data.get("result") or {}
        self.stdout.write("\n=== result: ключи верхнего уровня ===\n")
        self.stdout.write(json.dumps(list(result.keys()), ensure_ascii=False) + "\n")

        docs = result.get("Документ") or []
        if not docs:
            self.stdout.write("\nДокументов в result.Документ нет.\n")
            return
        self.stdout.write(f"\n=== первый документ (всего {len(docs)}): ключи ===\n")
        doc = docs[0]
        self.stdout.write(json.dumps(list(doc.keys()), ensure_ascii=False) + "\n")
        self.stdout.write("\n=== первый документ: поля (значения укорочены) ===\n")
        for k in sorted(doc.keys()):
            v = doc[k]
            if k == "Вложение" and isinstance(v, list):
                self.stdout.write(f"  {k}: [вложений: {len(v)}]\n")
                for i, att in enumerate(v[:3]):
                    if isinstance(att, dict):
                        self.stdout.write(f"    [{i}] ключи: {list(att.keys())}\n")
                        fl = (att.get("Файл") or {})
                        self.stdout.write(f"         Файл ключи: {list(fl.keys())}\n")
                        for fk, fv in (fl.items() or []):
                            if fk == "ДвоичныеДанные" and isinstance(fv, str):
                                self.stdout.write(f"         {fk}: <base64, {len(fv)} символов>\n")
                            else:
                                self.stdout.write(f"         {fk}: {_short(fv)}\n")
                if len(v) > 3:
                    self.stdout.write(f"    ... и ещё {len(v) - 3} вложений\n")
            else:
                self.stdout.write(f"  {k}: {_short(v)}\n")
        self.stdout.write("\n=== конец dump ===\n\n")

    def _collect_from_local_files(self, options) -> dict[str, tuple[str, str]]:
        """Сканирует Document.files (локальные XML)."""
        statuses = options["statuses"]
        if not statuses:
            statuses = ["SENT", "CONFIRMED", "UPLOADED"]

        media_root = Path(getattr(settings, "MEDIA_ROOT", "") or "").resolve()
        if not media_root.is_dir():
            self.stdout.write(
                self.style.WARNING(f"MEDIA_ROOT не задан или не каталог: {media_root}")
            )

        docs = Document.objects.filter(status__in=statuses).order_by("-created_at")
        total_docs = docs.count()
        self.stdout.write(f"Документов к просмотру: {total_docs} (статусы: {statuses})")

        inn_to_data: dict[str, tuple[str, str]] = {}

        for doc in docs.iterator(chunk_size=200):
            files = doc.files or []
            if not isinstance(files, list):
                continue
            for rel in files:
                if not rel or not isinstance(rel, str):
                    continue
                path = (media_root / rel.strip().lstrip("/")).resolve()
                if not path.suffix.lower() in (".xml",):
                    continue
                if not path.is_file():
                    continue
                data = _get_extract_our_org()(str(path))
                if not data:
                    continue
                inn = data["inn"]
                kpp = data["kpp"]
                name = data.get("name") or f"ИНН {inn}"
                if inn not in inn_to_data:
                    inn_to_data[inn] = (kpp, name[:255])

        self.stdout.write(f"Найдено уникальных ИНН с КПП в XML: {len(inn_to_data)}")
        return inn_to_data

    def _update_organizations(self, inn_to_data: dict[str, tuple[str, str]], dry: bool, sync_certs: bool, ensure_org: bool):
        """Обновить Organization и Certificate по собранным данным."""
        ok = skip = 0
        for inn, (kpp, name) in sorted(inn_to_data.items()):
            org = Organization.objects.filter(inn=inn).first()
            if not org:
                if not ensure_org:
                    self.stdout.write(
                        self.style.WARNING(f"ИНН {inn}: нет Organization (добавьте --ensure-organization)")
                    )
                    skip += 1
                    continue
                if dry:
                    self.stdout.write(f"ИНН {inn} → КПП {kpp} (создали бы Organization)")
                    ok += 1
                    continue
                with transaction.atomic():
                    Organization.objects.create(inn=inn, kpp=kpp, name=name)
                    if sync_certs:
                        Certificate.objects.filter(inn=inn).update(kpp=kpp)
                self.stdout.write(f"ИНН {inn} → КПП {kpp} (Organization создана)")
                ok += 1
                continue

            if org.kpp == kpp and not dry:
                skip += 1
                continue

            self.stdout.write(f"ИНН {inn}: КПП {org.kpp!r} → {kpp!r} ({name[:50]})")

            if dry:
                ok += 1
                continue

            with transaction.atomic():
                Organization.objects.filter(pk=org.pk).update(kpp=kpp)
                if sync_certs:
                    Certificate.objects.filter(inn=inn).update(kpp=kpp)
            ok += 1

        self.stdout.write(
            self.style.SUCCESS(f"Готово: обновлено/принято {ok}, пропусков {skip}")
        )
        if dry:
            self.stdout.write(self.style.WARNING("--dry-run: в БД не писали"))
