import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

from django.core.management.base import BaseCommand
from django.db import close_old_connections, transaction

from reports.models import Certificate, Organization
from reports.services.sbis import (
    CertInvalidNoRetryError,
    auth_sbis_by_cert,
    export_cert_der,
    get_thumbprint_from_cert,
    sbis_rpc,
)


def _process_one_inn_sbis(inn, csptest_name, date_from_str, date_to_str):
    try:
        return _process_one_inn_sbis_impl(inn, csptest_name, date_from_str, date_to_str)
    finally:
        close_old_connections()


def _process_one_inn_sbis_impl(inn, csptest_name, date_from_str, date_to_str):
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

        top_org = result.get("Организация") or {}
        top_svul = top_org.get("СвЮЛ") or result.get("СвЮЛ") or {}
        top_inn = (top_org.get("ИНН") or top_svul.get("ИНН") or "").strip()
        top_kpp = (top_org.get("КПП") or top_svul.get("КПП") or result.get("КПП") or "").strip()
        if top_inn == inn and top_kpp and len(top_kpp) == 9 and top_kpp.isdigit():
            name = (top_org.get("Наименование") or top_svul.get("НаимОрг") or f"ИНН {inn}")[:255]
            return (inn, (top_kpp, name), False, f"КПП: {top_kpp}")

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


def _kpp_inn_from_doc_json(doc, our_inn):
    if not doc:
        return None
    our_org = doc.get("НашаОрганизация") or doc.get("Организация") or {}
    svul = our_org.get("СвЮЛ") or doc.get("СвЮЛ") or {}
    doc_inn = (our_org.get("ИНН") or svul.get("ИНН") or doc.get("ИНН") or "").strip()
    if doc_inn != our_inn:
        return None
    kpp = (our_org.get("КПП") or svul.get("КПП") or doc.get("КПП") or "").strip()
    name = (
        our_org.get("Наименование")
        or our_org.get("НаимОрг")
        or svul.get("НаимОрг")
        or doc.get("Наименование")
        or ""
    ).strip()
    if not kpp or len(kpp) != 9 or not kpp.isdigit():
        return None
    return (kpp, name or f"ИНН {our_inn}")


def _is_revoked_or_untrusted_cert_error(message):
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
    help = "Заполнить КПП через СБИС.СписокДокументов"

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--sync-certificates", action="store_true")
        parser.add_argument("--ensure-organization", action="store_true")
        parser.add_argument("--year", type=int)
        parser.add_argument("--date-from", dest="date_from", default="")
        parser.add_argument("--date-to", dest="date_to", default="")
        parser.add_argument("--year-from-today", action="store_true")
        parser.add_argument("--inn", dest="inn_filter", default="")
        parser.add_argument("--dump-response", action="store_true")
        parser.add_argument("--workers", type=int, default=1, metavar="N")
        parser.add_argument("--force", action="store_true")

    def handle(self, *args, **options):
        inn_to_data = self._collect_from_sbis(options)
        if not inn_to_data:
            self.stdout.write(self.style.WARNING("Нечего обновлять."))
            return
        self._update_organizations(
            inn_to_data,
            options["dry_run"],
            options["sync_certificates"],
            options["ensure_organization"],
        )

    def _collect_from_sbis(self, options):
        year = options.get("year")
        date_from_str = (options.get("date_from") or "").strip()
        date_to_str = (options.get("date_to") or "").strip()

        if options.get("year_from_today"):
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

        inns = list(
            Certificate.objects.exclude(inn__isnull=True)
            .exclude(inn="")
            .values_list("inn", flat=True)
            .distinct()
        )
        inn_filter = (options.get("inn_filter") or "").strip()
        if inn_filter:
            if inn_filter not in inns:
                self.stdout.write(self.style.WARNING(f"ИНН {inn_filter} не найден в Certificate"))
                return {}
            inns = [inn_filter]
        if not inns:
            self.stdout.write(self.style.WARNING("Нет ИНН в Certificate"))
            return {}

        workers = max(1, int(options.get("workers") or 1))
        dump_response = options.get("dump_response")
        force = options.get("force")

        cert_map = {}
        for inn, csp in (
            Certificate.objects.filter(has_private_key=True)
            .exclude(csptest_name__isnull=True)
            .exclude(inn__isnull=True)
            .exclude(inn="")
            .values_list("inn", "csptest_name")
        ):
            if inn in inns and inn not in cert_map:
                cert_map[inn] = csp
        candidate_inns = [inn for inn in sorted(set(inns)) if inn in cert_map]

        if not force:
            existing_kpp_inns = set()
            for row in (
                Organization.objects.filter(inn__in=candidate_inns)
                .exclude(kpp__isnull=True)
                .exclude(kpp="")
                .values_list("inn", "kpp")
            ):
                inn, kpp = row
                if kpp and len(str(kpp).strip()) == 9 and str(kpp).strip().isdigit():
                    existing_kpp_inns.add(inn)
            candidate_inns = [inn for inn in candidate_inns if inn not in existing_kpp_inns]

        tasks = [(inn, cert_map[inn]) for inn in candidate_inns]
        total_inns = len(tasks)
        if not tasks:
            self.stdout.write(self.style.WARNING("Нет ИНН с сертификатом для запроса СБИС"))
            return {}

        inn_to_data = {}

        if workers <= 1 or dump_response:
            for idx, (inn, csptest_name) in enumerate(tasks, 1):
                self.stdout.write(f"[{idx}/{total_inns}] ИНН {inn}...")
                if dump_response and idx == 1:
                    cert_path = f"/tmp/sbis_kpp_docs_{inn}.cer"
                    export_cert_der(csptest_name, cert_path)
                    thumbprint = get_thumbprint_from_cert(cert_path)
                    session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
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
                    self._dump_sbis_list_response(data)
                    return {}
                res_inn, result, _del, msg = _process_one_inn_sbis(inn, csptest_name, date_from_str, date_to_str)
                if result:
                    inn_to_data[res_inn] = result
                    self.stdout.write(f"  {msg}")
                else:
                    style = self.style.ERROR if "удалён из БД" in msg else self.style.WARNING
                    self.stdout.write(style(f"  {msg}"))
        else:
            lock = threading.Lock()
            done = [0]

            def _collect(r):
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

    def _dump_sbis_list_response(self, data):
        result = data.get("result") or {}
        self.stdout.write(json.dumps(list(result.keys()), ensure_ascii=False))
        docs = result.get("Документ") or []
        if docs:
            self.stdout.write(json.dumps(list(docs[0].keys()), ensure_ascii=False))

    def _update_organizations(self, inn_to_data, dry, sync_certs, ensure_org):
        ok = skip = 0
        for inn, (kpp, name) in sorted(inn_to_data.items()):
            org = Organization.objects.filter(inn=inn).first()
            if not org:
                if not ensure_org:
                    self.stdout.write(self.style.WARNING(f"ИНН {inn}: нет Organization"))
                    skip += 1
                    continue
                if dry:
                    self.stdout.write(f"ИНН {inn} → КПП {kpp}")
                    ok += 1
                    continue
                with transaction.atomic():
                    Organization.objects.create(inn=inn, kpp=kpp, name=name)
                    if sync_certs:
                        Certificate.objects.filter(inn=inn).update(kpp=kpp)
                ok += 1
                continue

            if org.kpp == kpp and not dry:
                skip += 1
                continue

            if dry:
                ok += 1
                continue

            with transaction.atomic():
                Organization.objects.filter(pk=org.pk).update(kpp=kpp)
                if sync_certs:
                    Certificate.objects.filter(inn=inn).update(kpp=kpp)
            ok += 1

        self.stdout.write(self.style.SUCCESS(f"Готово: обновлено {ok}, пропусков {skip}"))
