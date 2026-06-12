"""
Получить требования ФНС (файлы PDF в base64) за последние N дней по всем компаниям из БД
и сохранить в таблицу RequirementDocument с дедупликацией.

Дедупликация:
  1) По (inn, sbis_doc_id) — если документ уже есть, пропускаем.
  2) По (inn, document_date, content_sha256) — при повторном сканировании не плодим
     одинаковые по содержимому документы за одну дату.

Кэш «уже сканировали сегодня»:
  Запись в БД ставится только если проход завершился *полностью* (без исключения), список
  получен, по всем позициям incoming отработано без ошибок скачивания и без «есть документ,
  но нет этапа для скачивания». Исключение (в т.ч. Too many open files) — кэш не пишется.
  Полная перепроверка: --force.

Фильтр по дате *документа* (после списка):
  СБИС в СписокСлужебныхЭтапов может вернуть старые редакции (напр. 2024 г.), хотя ДатаС/ДатаПо
  задают другое окно. Перед скачиванием по умолчанию отбираем только документы, у которых
  дата из ответа (Редакция/ДатаВремя и т.д.) попадает в [сегодня−N дней … сегодня].
  Отключить: --download-any-doc-date.

Пример:
  python manage.py fetch_requirements_all_companies
  python manage.py fetch_requirements_all_companies --days 10 --dry-run
  python manage.py fetch_requirements_all_companies --limit 5
  python manage.py fetch_requirements_all_companies --force
"""
import base64
import hashlib
import io
import logging
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timedelta

from django.core.management.base import BaseCommand
from django.db import transaction
from django.db import close_old_connections
from django.utils import timezone

from reports.models import Certificate, RequirementDocument, RequirementFetchScanState
from reports.requirement_file_sniff import guess_requirement_extension
from reports.services.sbis import sbis_list_service_stages, fetch_requirement_file_b64


logger = logging.getLogger(__name__)

# Ключевые слова в названии документа для фильтра «похоже на требование ФНС»
REQUIREMENT_KEYWORDS = (
    "требование",
    "фнс",
    "налоговая",
    "сверка",
    "уведомление",
    "инспекция",
    "ифнс",
    "акт сверки",
)


def parse_document_date(doc: dict) -> datetime | None:
    """
    Из документа СБИС (ответ СписокСлужебныхЭтапов) извлечь дату документа.
    Проверяем: верхний уровень (ДатаВремяСоздания и т.д.), затем Редакция[0].ДатаВремя.
    """
    def parse_val(val) -> datetime | None:
        if val is None:
            return None
        if isinstance(val, datetime):
            return val
        s = (val if isinstance(val, str) else str(val)).strip()
        if not s:
            return None
        formats = (
            "%d.%m.%Y %H:%M:%S",
            "%d.%m.%Y %H.%M.%S",  # СБИС иногда отдаёт время с точками: 29.05.2018 10.55.32
            "%d.%m.%Y %H:%M",
            "%d.%m.%Y",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        )
        for fmt in formats:
            try:
                return datetime.strptime(s[: len(fmt) + 12].strip(), fmt)
            except ValueError:
                continue
        return None

    # Сначала поля верхнего уровня
    for key in ("ДатаВремяСоздания", "ДатаСоздания", "ДатаПоступления", "ДатаДокумента", "Дата"):
        dt = parse_val(doc.get(key))
        if dt is not None:
            return dt
    # В ответе СписокСлужебныхЭтапов дата часто в Редакция[0].ДатаВремя
    redakcia = doc.get("Редакция")
    if isinstance(redakcia, list) and redakcia:
        first = redakcia[0] if isinstance(redakcia[0], dict) else None
        if first:
            dt = parse_val(first.get("ДатаВремя"))
            if dt is not None:
                return dt
    return None


def pick_service_stage_id(doc: dict) -> str | None:
    """
    Выбрать этап с действием «Обработать служебное» (или первый служебный этап).
    Возвращает Идентификатор этапа или None.
    """
    stages = doc.get("Этап") or []
    if not isinstance(stages, list):
        return None
    action_name = "Обработать служебное"
    for st in stages:
        if not isinstance(st, dict):
            continue
        stage_id = (st.get("Идентификатор") or "").strip()
        if not stage_id:
            continue
        actions = st.get("Действие") or []
        if not isinstance(actions, list):
            actions = [actions] if isinstance(actions, dict) else []
        for a in actions:
            if isinstance(a, dict) and (a.get("Название") or "").strip() == action_name:
                return stage_id
        if (st.get("Служебный") or "").strip() == "Да":
            return stage_id
    return (stages[0].get("Идентификатор") or "").strip() or None if stages else None


def is_requirement_like(doc: dict) -> bool:
    """Проверить, похож ли документ на требование ФНС (направление + название)."""
    direction = (doc.get("Направление") or "").strip()
    if direction != "Входящий":
        return False
    name = (doc.get("Название") or "").lower()
    return any(kw in name for kw in REQUIREMENT_KEYWORDS)


def is_requirement_in_client_date_window(doc: dict, win_start: date, win_end: date) -> bool:
    """
    Дата документа из карточки СБИС (parse_document_date) в пределах [win_start, win_end].
    Если дату разобрать нельзя — не скачиваем (иначе подтянутся старые редакции).
    """
    dt = parse_document_date(doc)
    if dt is None:
        return False
    d = dt.date()
    return win_start <= d <= win_end


def unpack_zip_and_pick_file(zip_bytes: bytes) -> tuple[bytes, str]:
    """
    Если содержимое — ZIP, распаковываем и возвращаем один файл (предпочитаем PDF, иначе первый).
    Возвращает (содержимое_байты, расширение с точкой, напр. .pdf или .xml).
    Если не ZIP — возвращает (zip_bytes, расширение по сигнатуре).
    """
    if not zip_bytes.startswith(b"PK\x03\x04"):
        return zip_bytes, guess_requirement_extension(zip_bytes)
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
        names = zf.namelist()
        chosen_name = None
        chosen_content = None
        for n in names:
            content = zf.read(n)
            if content.startswith(b"%PDF") or (n or "").lower().endswith(".pdf"):
                chosen_name = n
                chosen_content = content
                break
        if chosen_content is None and names:
            chosen_name = names[0]
            chosen_content = zf.read(chosen_name)
        zf.close()
        if chosen_content is None:
            return zip_bytes, ".bin"
        ext = guess_requirement_extension(chosen_content)
        if ext == ".bin" and (chosen_name or "").lower().endswith(".xml"):
            ext = ".xml"
        return chosen_content, ext
    except Exception:
        return zip_bytes, ".bin"


def _process_one_cert(
    idx: int,
    total_orgs: int,
    inn: str,
    kpp: str,
    date_from_str: str,
    date_to_str: str,
    date_from: datetime,
    date_to: datetime,
    page_size: int,
    dry_run: bool,
    quiet: bool,
    write_fn,
    *,
    client_date_filter: bool = True,
    window_key: str | None = None,
    scan_date=None,
    record_scan_state: bool = False,
) -> dict:
    """
    Обработать одну организацию (ИНН/КПП). Возвращает словарь со счётчиками для агрегации.
    write_fn(msg, style=None) вызывается с блокировкой снаружи для вывода в консоль.
    """
    stats = {
        "skipped_no_kpp": 0,
        "list_error": 0,
        "docs_found": 0,
        "skipped_outside_window": 0,
        "skipped_no_stage": 0,
        "skipped_no_doc_date": 0,
        "skipped_dup_doc_id": 0,
        "skipped_dup_sha": 0,
        "saved": 0,
        "fetch_error": 0,
        "dates_updated": 0,
    }
    # True только если дошли до конца обработки incoming без исключения и выполнены критерии ниже
    scan_eligible_for_cache = False
    try:
        close_old_connections()
        if not kpp:
            stats["skipped_no_kpp"] = 1
            if not quiet and idx <= 5:
                write_fn(f"  [{idx}/{total_orgs}] ИНН {inn}: пропуск — нет КПП в Certificate.", "warning")
            return stats

        if not quiet:
            write_fn(f"  [{idx}/{total_orgs}] ИНН {inn} (КПП {kpp}): запрос СписокСлужебныхЭтапов...", None)

        result = sbis_list_service_stages(
            inn,
            kpp=kpp,
            org_name="",
            date_from=date_from_str,
            date_to=date_to_str,
            page_size=page_size,
            only_reporting=False,
        )
        if not result.get("success"):
            stats["list_error"] = 1
            err = result.get("error") or {}
            msg = (err.get("message", str(result)) or "")[:120]
            if not quiet:
                write_fn(f"      Ошибка СписокСлужебныхЭтапов: {msg}", "error")
            return stats

        docs = (result.get("result") or {}).get("docs") or []
        win_start = date_from.date()
        win_end = date_to.date()
        raw_incoming = [d for d in docs if is_requirement_like(d)]
        stats["docs_found"] = len(raw_incoming)
        if client_date_filter:
            incoming = []
            for d in raw_incoming:
                if is_requirement_in_client_date_window(d, win_start, win_end):
                    incoming.append(d)
                else:
                    stats["skipped_outside_window"] += 1
                    if not quiet:
                        pdt = parse_document_date(d)
                        ds = pdt.date().isoformat() if pdt else "нет даты"
                        tit = ((d.get("Название") or "")[:40] or (d.get("Идентификатор") or "")[:20])
                        if len((d.get("Название") or "")) > 40:
                            tit += "..."
                        write_fn(
                            f"      — {tit}: вне окна {win_start}…{win_end} (дата док.: {ds}), пропуск скачивания",
                            None,
                        )
        else:
            incoming = raw_incoming
        if not quiet:
            write_fn(
                f"      Получено документов: {len(docs)}, по ключевым словам: {len(raw_incoming)}"
                + (
                    f", к скачиванию после фильтра по дате док.: {len(incoming)}"
                    if client_date_filter
                    else ""
                ),
                None,
            )

        # Обновить даты у уже существующих записей по данным из этого же ответа СБИС
        doc_id_to_date = {}
        for d in docs:
            doc_id = (d.get("Идентификатор") or "").strip()
            if not doc_id:
                continue
            dt = parse_document_date(d)
            if dt is not None:
                doc_id_to_date[doc_id] = dt.date()
        if doc_id_to_date:
            for r in RequirementDocument.objects.filter(inn=inn, sbis_doc_id__in=doc_id_to_date.keys()):
                new_date = doc_id_to_date.get(r.sbis_doc_id)
                if new_date and r.document_date != new_date:
                    old_date = r.document_date
                    ext = ".pdf"
                    if r.storage_file_name and "." in r.storage_file_name:
                        ext = "." + r.storage_file_name.rsplit(".", 1)[-1].lower()
                    new_storage_name = f"Требование ФНС ({r.inn}) ({new_date}){ext}"
                    if not dry_run:
                        with transaction.atomic():
                            r.document_date = new_date
                            r.storage_file_name = new_storage_name
                            r.save(update_fields=["document_date", "storage_file_name"])
                    stats["dates_updated"] += 1
                    if not quiet:
                        write_fn(f"      — обновлена дата у doc_id={r.sbis_doc_id[:20]}...: {old_date} -> {new_date}", None)

        for doc in incoming:
            doc_id = (doc.get("Идентификатор") or "").strip()
            if not doc_id:
                continue
            stage_id = pick_service_stage_id(doc)
            if not stage_id:
                stats["skipped_no_stage"] += 1
                if not quiet:
                    write_fn(f"      — документ {doc_id[:24]}...: нет этапа, пропуск", "warning")
                continue

            doc_title_short = ((doc.get("Название") or "")[:50] or doc_id[:20]) + ("..." if len(doc.get("Название") or "") > 50 else "")

            if RequirementDocument.objects.filter(inn=inn, sbis_doc_id=doc_id).exists():
                stats["skipped_dup_doc_id"] += 1
                if not quiet:
                    write_fn(f"      — {doc_title_short}: уже в БД (doc_id), пропуск", None)
                continue

            doc_date = parse_document_date(doc)
            if not doc_date and client_date_filter:
                stats["skipped_no_doc_date"] += 1
                if not quiet:
                    write_fn(f"      — {doc_title_short}: нет даты документа в карточке, пропуск", "warning")
                continue
            document_date = doc_date.date() if doc_date else date_from.date()
            doc_title = (doc.get("Название") or "")[:512]

            if not quiet:
                write_fn(f"      — {doc_title_short}: скачивание PDF...", None)

            fetch = fetch_requirement_file_b64(
                inn,
                kpp=kpp,
                requirement_doc_id=doc_id,
                requirement_stage_id=stage_id,
            )
            if not fetch.get("success"):
                stats["fetch_error"] += 1
                err = (fetch.get("error") or {}).get("message", "")[:80]
                if not quiet:
                    write_fn(f"        Ошибка: {err}", "error")
                continue

            b64 = (fetch.get("result") or {}).get("b64") or ""
            if not b64:
                stats["fetch_error"] += 1
                if not quiet:
                    write_fn("        Ошибка: пустой ответ (нет b64)", "error")
                continue

            raw_bytes = base64.b64decode(b64)
            raw_bytes, ext = unpack_zip_and_pick_file(raw_bytes)
            b64 = base64.b64encode(raw_bytes).decode("ascii")
            content_sha256 = hashlib.sha256(raw_bytes).hexdigest()
            storage_file_name = f"Требование ФНС ({inn}) ({document_date}){ext}"

            if RequirementDocument.objects.filter(
                inn=inn,
                document_date=document_date,
                content_sha256=content_sha256,
            ).exists():
                stats["skipped_dup_sha"] += 1
                if not quiet:
                    write_fn(f"        Пропуск: дубль по содержимому за {document_date}.", None)
                continue

            if not dry_run:
                with transaction.atomic():
                    RequirementDocument.objects.create(
                        inn=inn,
                        document_date=document_date,
                        sbis_doc_id=doc_id,
                        sbis_stage_id=stage_id,
                        doc_title=doc_title,
                        content_sha256=content_sha256,
                        file_b64=b64,
                        storage_file_name=storage_file_name,
                    )
            stats["saved"] += 1
            if not quiet:
                size = len(raw_bytes)
                size_str = f"{size // 1024} КБ" if size >= 1024 else f"{size} Б"
                write_fn(f"        Сохранён. Дата док.: {document_date}, размер {size_str}" + (" (dry-run)" if dry_run else ""), "success")

        # Сюда попадаем только без исключения в теле try (в т.ч. после полного цикла по incoming)
        scan_eligible_for_cache = (
            stats.get("list_error", 0) == 0
            and stats.get("fetch_error", 0) == 0
            and stats.get("skipped_no_stage", 0) == 0
            and stats.get("skipped_no_doc_date", 0) == 0
        )
    finally:
        if (
            record_scan_state
            and window_key
            and scan_date is not None
            and stats.get("skipped_no_kpp", 0) == 0
            and scan_eligible_for_cache
        ):
            try:
                RequirementFetchScanState.objects.update_or_create(
                    inn=inn,
                    window_key=window_key,
                    scan_date=scan_date,
                    defaults={},
                )
            except Exception as e:
                logger.warning("RequirementFetchScanState update_or_create: %s", e)
        close_old_connections()
    return stats


class Command(BaseCommand):
    help = "Получить требования за последние N дней по всем компаниям (Certificate) и сохранить в RequirementDocument"

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=10,
            help="За сколько последних дней запрашивать требования (по умолчанию 10)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Не сохранять в БД, только вывести, что бы сделали",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=0,
            help="Максимум организаций обработать (0 — все)",
        )
        parser.add_argument(
            "--page-size",
            type=int,
            default=50,
            help="Размер страницы СписокСлужебныхЭтапов (по умолчанию 50)",
        )
        parser.add_argument(
            "-q",
            "--quiet",
            action="store_true",
            help="Минимальный вывод (только итог)",
        )
        parser.add_argument(
            "--workers",
            type=int,
            default=1,
            help="Число потоков на первом раунде (по умолчанию 1). Максимум в коде: 8. При EMFILE / «Too many open files» используйте 1–2 или ulimit -n 8192.",
        )
        parser.add_argument(
            "--retry-workers",
            type=int,
            default=1,
            help="Потоков на раундах 2+ (повтор по ошибкам). По умолчанию 1 — последовательно, меньше риск исчерпать открытые файлы.",
        )
        parser.add_argument(
            "--round-sleep",
            type=int,
            default=90,
            help="Пауза в секундах между раундами при наличии ошибок (по умолчанию 90).",
        )
        parser.add_argument(
            "--max-rounds",
            type=int,
            default=5,
            help="Максимум раундов: при ошибках (список/скачивание) повторять проход по необработанным ИНН (по умолчанию 5).",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Игнорировать кэш «уже успешно сканировали сегодня» и опросить все организации заново.",
        )
        parser.add_argument(
            "--download-any-doc-date",
            action="store_true",
            help="Не фильтровать по дате документа на стороне приложения (скачивать все «требования» из ответа списка, как раньше).",
        )

    def handle(self, *args, **options):
        days = max(1, options["days"])
        dry_run = options["dry_run"]
        limit = options["limit"]
        page_size = options["page_size"]
        quiet = options.get("quiet", False)
        workers = max(1, min(8, int(options.get("workers", 1))))
        retry_workers = max(1, min(8, int(options.get("retry_workers", 1))))
        round_sleep_sec = max(15, int(options.get("round_sleep", 90)))
        max_rounds = max(1, int(options.get("max_rounds", 5)))
        client_date_filter = not bool(options.get("download_any_doc_date"))

        date_to = datetime.now()
        date_from = date_to - timedelta(days=days)
        date_from_str = date_from.strftime("%d.%m.%Y")
        date_to_str = date_to.strftime("%d.%m.%Y")
        window_key = f"{date_from_str}|{date_to_str}"
        scan_date = timezone.localdate()
        record_scan_state = not dry_run
        use_skip_cache = not options.get("force", False) and not dry_run

        def get_certs_for_inns(inn_list):
            """По списку ИНН вернуть список сертификатов (по одному на ИНН, с КПП по возможности)."""
            certs_out = []
            for inn_val in inn_list:
                c = (
                    Certificate.objects.filter(
                        inn=inn_val,
                        csptest_name__isnull=False,
                    )
                    .exclude(csptest_name="")
                    .filter(is_active=True)
                    .order_by("-kpp")
                    .first()
                )
                if c:
                    certs_out.append(c)
            return certs_out

        inns_with_cert = (
            Certificate.objects.filter(
                csptest_name__isnull=False,
            )
            .exclude(csptest_name="")
            .filter(is_active=True)
            .values_list("inn", flat=True)
            .distinct()
        )
        certs = get_certs_for_inns(list(inns_with_cert))

        skipped_cached = 0
        if use_skip_cache:
            filtered = []
            for c in certs:
                inn_val = (c.inn or "").strip()
                if RequirementFetchScanState.objects.filter(
                    inn=inn_val, window_key=window_key, scan_date=scan_date
                ).exists():
                    skipped_cached += 1
                else:
                    filtered.append(c)
            certs = filtered
            if skipped_cached and not quiet:
                self.stdout.write(
                    self.style.WARNING(
                        f"Пропущено по кэшу «уже успешно сканировали сегодня» ({scan_date}) для окна {window_key}: "
                        f"{skipped_cached} орг. Полная перепроверка: --force"
                    )
                )

        if limit > 0:
            certs = certs[:limit]

        cache_note = ""
        if use_skip_cache:
            cache_note = " Кэш «сканировали сегодня»: включён (--force отключает)."
        elif dry_run:
            cache_note = " Кэш не читается и не пишется (--dry-run)."
        elif options.get("force"):
            cache_note = " Кэш «сканировали сегодня»: отключён (--force)."

        date_filter_note = ""
        if client_date_filter:
            date_filter_note = " Фильтр по дате документа в ответе СБИС: включён (см. --download-any-doc-date)."
        else:
            date_filter_note = " Фильтр по дате документа: выключен — скачиваем все подходящие из списка."

        self.stdout.write(
            f"Период: {date_from_str} — {date_to_str}. Организаций к обходу: {len(certs)}. Раундов повтора при ошибках: до {max_rounds}.{cache_note}{date_filter_note}"
        )
        self.stdout.write(
            f"Параллелизм: раунд 1 — {workers} поток(ов), раунды 2+ — {retry_workers} "
            f"(--workers / --retry-workers); пауза между раундами при ошибках: {round_sleep_sec} с."
        )
        if workers > 4:
            self.stdout.write(
                self.style.WARNING(
                    "При «Too many open files» уменьшите --workers до 1–2, задайте --retry-workers 1, "
                    "увеличьте ulimit -n на сервере (например 8192)."
                )
            )
        if dry_run:
            self.stdout.write(self.style.WARNING("Режим --dry-run: в БД ничего не пишем."))
        if not quiet:
            self.stdout.write("")

        stats = {
            "skipped_no_kpp": 0,
            "list_error": 0,
            "docs_found": 0,
            "skipped_outside_window": 0,
            "skipped_no_stage": 0,
            "skipped_no_doc_date": 0,
            "skipped_dup_doc_id": 0,
            "skipped_dup_sha": 0,
            "saved": 0,
            "fetch_error": 0,
            "dates_updated": 0,
            "skipped_cached": skipped_cached,
        }
        lock = threading.Lock()

        def write_fn(msg: str, style: str | None = None):
            with lock:
                if style == "error":
                    self.stdout.write(self.style.ERROR(msg))
                elif style == "warning":
                    self.stdout.write(self.style.WARNING(msg))
                elif style == "success":
                    self.stdout.write(self.style.SUCCESS(msg))
                else:
                    self.stdout.write(msg)

        certs_to_try = certs
        # После EMFILE на любом раунде — дальше только 1 поток, иначе снова исчерпываются FD
        throttle_after_emfile = False

        for round_num in range(1, max_rounds + 1):
            if not certs_to_try:
                break
            total_orgs = len(certs_to_try)
            round_workers = workers if round_num == 1 else retry_workers
            if throttle_after_emfile:
                round_workers = 1

            if round_num > 1:
                if not quiet:
                    self.stdout.write("")
                write_fn(
                    f"Раунд {round_num}: повтор по {total_orgs} ИНН (ошибки в прошлом проходе). "
                    f"Потоков в этом раунде: {round_workers}"
                    + (" (принудительно 1 из‑за ранее пойманного EMFILE)" if throttle_after_emfile else ""),
                    "warning",
                )

            round_failed_inns = set()

            if round_workers <= 1:
                for idx, cert in enumerate(certs_to_try, 1):
                    inn = (cert.inn or "").strip()
                    kpp = (getattr(cert, "kpp", None) or "").strip()
                    try:
                        s = _process_one_cert(
                            idx, total_orgs, inn, kpp,
                            date_from_str, date_to_str, date_from, date_to,
                            page_size, dry_run, quiet, write_fn,
                            client_date_filter=client_date_filter,
                            window_key=window_key,
                            scan_date=scan_date,
                            record_scan_state=record_scan_state,
                        )
                        for k in stats:
                            stats[k] += s.get(k, 0)
                        if s.get("list_error") or s.get("fetch_error"):
                            round_failed_inns.add(inn)
                        if s.get("skipped_no_kpp") and stats["skipped_no_kpp"] == 6 and not quiet:
                            write_fn("  ... (остальные ИНН без КПП не выводятся)", "warning")
                    except Exception as e:
                        write_fn(f"  ИНН {inn}: исключение — {e}", "error")
                        stats["list_error"] += 1
                        round_failed_inns.add(inn)
                        es = str(e)
                        if "Too many open files" in es or "Errno 24" in es:
                            throttle_after_emfile = True
            else:
                def task(item):
                    close_old_connections()
                    idx, cert = item
                    inn = (cert.inn or "").strip()
                    kpp = (getattr(cert, "kpp", None) or "").strip()
                    try:
                        return (
                            cert,
                            _process_one_cert(
                                idx,
                                total_orgs,
                                inn,
                                kpp,
                                date_from_str,
                                date_to_str,
                                date_from,
                                date_to,
                                page_size,
                                dry_run,
                                quiet,
                                write_fn,
                                client_date_filter=client_date_filter,
                                window_key=window_key,
                                scan_date=scan_date,
                                record_scan_state=record_scan_state,
                            ),
                        )
                    finally:
                        close_old_connections()

                if not quiet:
                    write_fn(
                        f"Пул: не более {round_workers} организаций одновременно (всего в раунде: {total_orgs})",
                        None,
                    )
                with ThreadPoolExecutor(max_workers=round_workers) as executor:
                    futures = {executor.submit(task, (idx, cert)): cert for idx, cert in enumerate(certs_to_try, 1)}
                    for future in as_completed(futures):
                        cert = futures[future]
                        try:
                            _, s = future.result()
                            for k in stats:
                                stats[k] += s.get(k, 0)
                            if s.get("list_error") or s.get("fetch_error"):
                                round_failed_inns.add((cert.inn or "").strip())
                        except Exception as e:
                            write_fn(f"  ИНН {(cert.inn or '')}: исключение — {e}", "error")
                            stats["list_error"] += 1
                            round_failed_inns.add((cert.inn or "").strip())
                            es = str(e)
                            if "Too many open files" in es or "Errno 24" in es:
                                throttle_after_emfile = True

            if not round_failed_inns:
                break
            certs_to_try = get_certs_for_inns(list(round_failed_inns))
            if certs_to_try and not quiet:
                write_fn(
                    f"Все потоки раунда завершены. Пауза {round_sleep_sec} с перед следующим раундом...",
                    None,
                )
            if certs_to_try:
                time.sleep(round_sleep_sec)

        self.stdout.write("")
        self.stdout.write(
            f"Готово. Пропущено по кэшу «уже сканировали сегодня»: {stats['skipped_cached']}, "
            f"пропущено (нет КПП): {stats['skipped_no_kpp']}, "
            f"ошибки списка: {stats['list_error']}, "
            f"документов по ключевым словам: {stats['docs_found']}, "
            f"пропущено (дата док. вне окна --days): {stats['skipped_outside_window']}, "
            f"пропущено (нет этапа для скачивания): {stats['skipped_no_stage']}, "
            f"пропущено (нет даты док. в карточке): {stats['skipped_no_doc_date']}, "
            f"пропущено (уже по doc_id): {stats['skipped_dup_doc_id']}, "
            f"пропущено (дубль по SHA за дату): {stats['skipped_dup_sha']}, "
            f"ошибки скачивания: {stats['fetch_error']}, "
            f"обновлено дат у существующих: {stats['dates_updated']}, "
            f"сохранено: {stats['saved']}."
        )
