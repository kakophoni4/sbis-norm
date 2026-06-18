"""
Массовая проверка авторизации СБИС по всем ИНН в БД.

Пример:
  docker compose exec web python manage.py test_sbis_auth_all --quiet
  docker compose exec web python manage.py test_sbis_auth_all --limit 20
  docker compose exec web python manage.py test_sbis_auth_all --output-dir /app/media/sbis_auth_scan

Полный прогон ~1004 ИНН (в screen/nohup):
  nohup docker compose exec -T web python manage.py test_sbis_auth_all --quiet --delay 0.5 \\
    > /tmp/sbis_auth_all.log 2>&1 &
  tail -f /tmp/sbis_auth_all.log
"""
import csv
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from django.core.management.base import BaseCommand
from django.utils import timezone as dj_timezone

from reports.models import Certificate
from reports.services.sbis_mail import SbisAuthError, SbisSessionService


ERROR_CATEGORY_RU = {
    "ok": "OK — session получен",
    "expired": "Сертификат просрочен",
    "expired_local": "Просрочен (not_after в БД, SBIS не вызывали)",
    "revoked_or_untrusted": "Отозван / не доверенный",
    "not_registered_in_sbis": "Не зарегистрирован в СБИС",
    "registration_pending": "Ожидает регистрации в СБИС",
    "umy_not_linked": "Нет PrivateKey Link в uMy",
    "proxy_error": "Ошибка прокси NodeMaven / сети",
    "no_cert": "Нет сертификата в БД",
    "other_error": "Прочая ошибка",
}


def classify_sbis_error(message: str) -> str:
    m = (message or "").lower()
    if "no certificate found" in m or "0x2000012d" in m:
        return "umy_not_linked"
    if "отозван" in m or "не является доверенным" in m or "выберите другой сертификат" in m:
        return "revoked_or_untrusted"
    if "не зарегистрирован" in m or "ни в одном кабинете" in m:
        return "not_registered_in_sbis"
    if "просрочен" in m or "аутентификация по просроченному" in m:
        return "expired"
    if "регистрация клиента" in m or "схема для клиента" in m:
        return "registration_pending"
    if "proxy/http failed" in m or "transport error" in m or "не удалось подобрать живой прокси" in m:
        return "proxy_error"
    if "не указано имя контейнера" in m or "не найден активный сертификат" in m:
        return "no_cert"
    return "other_error"


FAIL_FAST_CATEGORIES = frozenset(
    {
        "revoked_or_untrusted",
        "not_registered_in_sbis",
        "expired",
        "expired_local",
        "registration_pending",
        "umy_not_linked",
    }
)


def pick_certs_for_inn(inn: str, try_all: bool):
    qs = Certificate.objects.filter(inn=inn, has_private_key=True, is_active=True)
    if not try_all:
        linked = qs.exclude(hdimage_path="").exclude(hdimage_path__isnull=True).order_by(
            "-not_after", "-id"
        )
        if linked.exists():
            return [linked.first()]
        best = qs.order_by("-not_after", "-id").first()
        return [best] if best else []
    return list(qs.order_by("-not_after", "-id"))


def _fmt_dt(dt) -> str:
    if not dt:
        return ""
    if dj_timezone.is_naive(dt):
        dt = dj_timezone.make_aware(dt, timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _cert_expired(cert: Certificate, now) -> bool:
    na = cert.not_after
    if not na:
        return False
    if dj_timezone.is_naive(na):
        na = dj_timezone.make_aware(na, timezone.utc)
    return na <= now


class Command(BaseCommand):
    help = "Проверить авторизацию СБИС для всех ИНН и сохранить список валидных"

    def add_arguments(self, parser):
        parser.add_argument(
            "--output-dir",
            default="/app/media/sbis_auth_scan",
            help="Каталог для отчётов (CSV + valid_inns.txt)",
        )
        parser.add_argument("--limit", type=int, default=0, help="Ограничить число ИНН (0 = все)")
        parser.add_argument("--offset", type=int, default=0, help="Пропустить первые N ИНН")
        parser.add_argument(
            "--delay",
            type=float,
            default=1.0,
            help="Пауза между ИНН (сек), чтобы не душить NodeMaven",
        )
        parser.add_argument(
            "--inn",
            action="append",
            default=[],
            help="Проверить только указанные ИНН (можно несколько --inn)",
        )
        parser.add_argument(
            "--quiet",
            action="store_true",
            help="Меньше логов SBIS в консоли",
        )
        parser.add_argument(
            "--try-all-certs",
            action="store_true",
            help="Перебирать все сертификаты ИНН (по умолчанию — один лучший из uMy)",
        )
        parser.add_argument(
            "--call-sbis-for-expired",
            action="store_true",
            help="Вызывать СБИС даже для просроченных по not_after (по умолчанию просроченные только в CSV)",
        )

    def handle(self, *args, **options):
        skip_expired = not options["call_sbis_for_expired"]
        if options["quiet"]:
            for name in ("reports.services.sbis", "reports.services.sbis_mail"):
                logging.getLogger(name).setLevel(logging.WARNING)

        out_dir = Path(options["output_dir"])
        out_dir.mkdir(parents=True, exist_ok=True)
        now = dj_timezone.now()
        ts = now.strftime("%Y%m%d_%H%M%S")
        csv_path = out_dir / f"sbis_auth_report_{ts}.csv"
        valid_path = out_dir / f"valid_inns_{ts}.txt"
        failed_path = out_dir / f"failed_inns_{ts}.txt"
        summary_path = out_dir / f"summary_{ts}.json"

        only_inns = [x.strip() for x in options["inn"] if x and x.strip()]
        inn_qs = (
            Certificate.objects.filter(has_private_key=True, is_active=True)
            .exclude(inn="")
            .values_list("inn", flat=True)
            .distinct()
            .order_by("inn")
        )
        if only_inns:
            inn_qs = inn_qs.filter(inn__in=only_inns)
        inns = list(inn_qs)
        if options["offset"]:
            inns = inns[options["offset"] :]
        if options["limit"]:
            inns = inns[: options["limit"]]

        total = len(inns)
        db_total = Certificate.objects.count()
        db_unique = (
            Certificate.objects.exclude(inn="").values_list("inn", flat=True).distinct().count()
        )
        db_auth = (
            Certificate.objects.filter(has_private_key=True, is_active=True)
            .exclude(inn="")
            .values_list("inn", flat=True)
            .distinct()
            .count()
        )
        self.stdout.write(f"ИНН к проверке: {total}")
        self.stdout.write(f"БД: записей={db_total}, уникальных ИНН={db_unique}, ИНН с uMy={db_auth}")
        if db_auth < 10 and db_total > 100:
            self.stdout.write(
                self.style.WARNING(
                    "Мало ИНН с has_private_key — сначала: "
                    "sbis_keys_install_linux.sh --install-only && sync_has_private_key (без --all)"
                )
            )
        self.stdout.write(f"Отчёт: {csv_path}")

        valid_inns: list[str] = []
        failed_inns: list[str] = []
        stats: dict[str, int] = {}

        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "inn",
                    "status",
                    "error_category",
                    "error_category_ru",
                    "certificate_id",
                    "csptest_name",
                    "thumbprint",
                    "not_before",
                    "not_after",
                    "expired_in_db",
                    "has_private_key",
                    "message",
                ]
            )

            def write_row(
                inn,
                status,
                cat,
                cert_obj,
                msg="",
            ):
                writer.writerow(
                    [
                        inn,
                        status,
                        cat,
                        ERROR_CATEGORY_RU.get(cat, cat),
                        cert_obj.id if cert_obj else "",
                        (cert_obj.csptest_name or "") if cert_obj else "",
                        (cert_obj.thumbprint or "") if cert_obj else "",
                        _fmt_dt(cert_obj.not_before) if cert_obj else "",
                        _fmt_dt(cert_obj.not_after) if cert_obj else "",
                        "yes" if cert_obj and _cert_expired(cert_obj, now) else "no",
                        "yes" if cert_obj and cert_obj.has_private_key else "no",
                        (msg or "")[:500],
                    ]
                )

            for idx, inn in enumerate(inns, start=1):
                certs = pick_certs_for_inn(inn, options["try_all_certs"])
                if not certs:
                    write_row(inn, "fail", "no_cert", None, "нет контейнера в БД")
                    stats["no_cert"] = stats.get("no_cert", 0) + 1
                    failed_inns.append(inn)
                    f.flush()
                    self.stdout.write(f"[{idx}/{total}] {inn} — no_cert")
                    continue

                ok = False
                last_cat = "other_error"
                last_msg = ""
                last_cert: Certificate | None = None

                for cert in certs:
                    last_cert = cert
                    if skip_expired and _cert_expired(cert, now):
                        last_cat = "expired_local"
                        last_msg = f"not_after={_fmt_dt(cert.not_after)}"
                        continue

                    try:
                        service = SbisSessionService(certificate=cert)
                        session_id = service.authenticate()
                        write_row(inn, "ok", "ok", cert, session_id)
                        valid_inns.append(inn)
                        stats["ok"] = stats.get("ok", 0) + 1
                        ok = True
                        self.stdout.write(self.style.SUCCESS(f"[{idx}/{total}] {inn} — OK (cert {cert.id})"))
                        break
                    except SbisAuthError as e:
                        last_msg = str(e)
                        last_cat = classify_sbis_error(last_msg)
                        if last_cat in FAIL_FAST_CATEGORIES:
                            break
                    except Exception as e:
                        last_msg = str(e)
                        last_cat = classify_sbis_error(last_msg)

                if not ok:
                    write_row(inn, "fail", last_cat, last_cert, last_msg)
                    stats[last_cat] = stats.get(last_cat, 0) + 1
                    failed_inns.append(inn)
                    self.stdout.write(
                        self.style.WARNING(
                            f"[{idx}/{total}] {inn} — {last_cat}: {ERROR_CATEGORY_RU.get(last_cat, last_cat)}"
                        )
                    )

                f.flush()
                if options["delay"] > 0 and idx < total:
                    time.sleep(options["delay"])

        valid_path.write_text("\n".join(valid_inns) + ("\n" if valid_inns else ""), encoding="utf-8")
        failed_path.write_text("\n".join(failed_inns) + ("\n" if failed_inns else ""), encoding="utf-8")
        summary = {
            "checked_inns": total,
            "valid_count": len(valid_inns),
            "failed_count": len(failed_inns),
            "stats": stats,
            "error_categories_ru": ERROR_CATEGORY_RU,
            "csv": str(csv_path),
            "valid_inns_file": str(valid_path),
            "failed_inns_file": str(failed_path),
        }
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(f"Валидных ИНН: {len(valid_inns)} / {total}"))
        self.stdout.write(f"С ошибкой:     {len(failed_inns)}")
        self.stdout.write(f"Валидные:      {valid_path}")
        self.stdout.write(f"С ошибками:    {failed_path}")
        self.stdout.write(f"CSV:           {csv_path}")
        self.stdout.write(f"Сводка JSON:   {summary_path}")
        for cat, n in sorted(stats.items(), key=lambda x: (-x[1], x[0])):
            ru = ERROR_CATEGORY_RU.get(cat, cat)
            self.stdout.write(f"  {cat} ({ru}): {n}")
