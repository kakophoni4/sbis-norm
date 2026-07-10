"""
Аудит готовности ЭЦП к отправке НДС (контейнер + uMy PrivateKey Link + пробная подпись).

  docker compose exec -T web python manage.py audit_cert_signing_ready
  docker compose exec -T web python manage.py audit_cert_signing_ready --sign-test
  docker compose exec -T web python manage.py audit_cert_signing_ready --only-inn 9707039440
  docker compose exec -T web python manage.py audit_cert_signing_ready --fix-csv /tmp/cert_audit.csv
"""
from __future__ import annotations

import csv
import os
import re
import tempfile
from collections import defaultdict

from django.core.management.base import BaseCommand
from django.utils import timezone as dj_timezone

from reports.models import Certificate
from reports.management.commands.scan_certificates import (
    parse_umy_thumbprint_link,
    verify_container_has_private_key,
)
from reports.services.sbis.crypto import (
    export_cert_der,
    get_thumbprint_from_cert,
    run_cmd,
    sign_xml_if_needed,
)
from reports.services.sbis.constants import CERTMGR_BIN


def _load_umy_index() -> dict[str, dict]:
    """thumbprint(lower, no spaces) -> {has_pk, container, subject_snip}"""
    out = run_cmd([CERTMGR_BIN, "-list", "-store", "uMy"], timeout_sec=180)
    idx: dict[str, dict] = {}
    cur_tp: str | None = None
    has_pk = False
    container = ""
    subject = ""
    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("SHA1 Thumbprint"):
            if cur_tp:
                idx[cur_tp] = {"has_pk": has_pk, "container": container, "subject": subject}
            parts = line.split(":", 1)
            cur_tp = re.sub(r"\s+", "", parts[1].strip()).lower() if len(parts) == 2 else None
            has_pk = False
            container = ""
            subject = ""
        elif cur_tp:
            if line.startswith("PrivateKey Link"):
                has_pk = "Yes" in line
            elif line.startswith("Container"):
                container = line.split(":", 1)[1].strip() if ":" in line else ""
            elif line.startswith("Subject") or line.startswith("Субъект"):
                subject = line.split(":", 1)[1].strip()[:80] if ":" in line else ""
    if cur_tp:
        idx[cur_tp] = {"has_pk": has_pk, "container": container, "subject": subject}
    return idx


class Command(BaseCommand):
    help = "Проверить контейнер + uMy PrivateKey Link (+ опционально cryptcp -sign) по Certificate"

    def add_arguments(self, parser):
        parser.add_argument("--only-inn", action="append", default=[], help="Только эти ИНН (можно несколько)")
        parser.add_argument(
            "--all-db",
            action="store_true",
            help="Все активные с csptest_name (по умолчанию только has_private_key=True)",
        )
        parser.add_argument(
            "--sign-test",
            action="store_true",
            help="Для OK по uMy сделать пробную cryptcp -sign (медленнее)",
        )
        parser.add_argument("--limit", type=int, default=0)
        parser.add_argument("--fix-csv", default="")

    def handle(self, *args, **options):
        only = [str(x).strip() for x in (options["only_inn"] or []) if str(x).strip()]
        qs = Certificate.objects.filter(is_active=True).exclude(csptest_name__isnull=True).exclude(csptest_name="")
        if not options["all_db"]:
            qs = qs.filter(has_private_key=True)
        if only:
            qs = qs.filter(inn__in=only)
        qs = qs.order_by("inn", "-id")

        # один лучший серт на ИНН
        by_inn: dict[str, Certificate] = {}
        for c in qs:
            if c.inn not in by_inn:
                by_inn[c.inn] = c
        inns = list(by_inn.keys())
        if options["limit"]:
            inns = inns[: options["limit"]]

        self.stdout.write(f"ИНН к проверке: {len(inns)}")
        self.stdout.write("Читаю uMy (один раз)...")
        try:
            umy = _load_umy_index()
        except Exception as e:
            self.stderr.write(f"Не удалось прочитать uMy: {e}")
            umy = {}
        self.stdout.write(
            f"  сертификатов в uMy: {len(umy)}, с PrivateKey Link: {sum(1 for v in umy.values() if v['has_pk'])}"
        )

        rows = []
        stats = defaultdict(int)

        for i, inn in enumerate(inns, 1):
            c = by_inn[inn]
            cont = (c.csptest_name or "").strip()
            status = "OK"
            detail = ""
            thumb = ""
            umy_pk = False
            cont_ok = False
            sign_ok = ""

            try:
                cont_ok = verify_container_has_private_key(cont, timeout=8)
            except Exception as e:
                cont_ok = False
                detail = f"verifycontext: {e}"

            if not cont_ok and not detail:
                status = "FAIL_CONTAINER"
                detail = "csptest -verifycontext failed"
            else:
                try:
                    cer = f"/tmp/audit_{inn}.cer"
                    export_cert_der(cont, cer)
                    thumb = get_thumbprint_from_cert(cer)
                    info = umy.get(thumb) or umy.get(thumb.lower())
                    if not info:
                        # fallback медленный per-thumb
                        linked, umy_cont = parse_umy_thumbprint_link(thumb)
                        umy_pk = linked
                        if not linked:
                            status = "FAIL_UMY"
                            detail = f"нет в uMy или PrivateKey Link=No (cont={umy_cont})"
                        else:
                            detail = f"uMy cont={umy_cont}"
                    else:
                        umy_pk = bool(info.get("has_pk"))
                        if not umy_pk:
                            status = "FAIL_UMY"
                            detail = f"в uMy без PrivateKey Link; store_cont={info.get('container')}"
                        else:
                            detail = f"uMy cont={info.get('container')}"
                except Exception as e:
                    status = "FAIL_EXPORT"
                    detail = str(e)[:200]

            if status == "OK" and options["sign_test"]:
                try:
                    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
                        f.write(b"<a/>")
                        path = f.name
                    sgn = sign_xml_if_needed(path, None, thumb, csptest_name=cont)
                    sign_ok = "YES" if sgn and os.path.exists(sgn) else "NO"
                    if sign_ok != "YES":
                        status = "FAIL_SIGN"
                        detail = "sign produced no file"
                except Exception as e:
                    status = "FAIL_SIGN"
                    sign_ok = "NO"
                    detail = str(e)[:240]
                finally:
                    try:
                        os.remove(path)
                        os.remove(path + ".sgn")
                    except Exception:
                        pass

            na = c.not_after
            expired = ""
            if na:
                now = dj_timezone.now()
                if dj_timezone.is_naive(na):
                    from datetime import timezone as dt_tz

                    na = dj_timezone.make_aware(na, dt_tz.utc)
                if na <= now:
                    expired = "EXPIRED"
                    if status == "OK":
                        status = "WARN_EXPIRED"

            stats[status] += 1
            row = {
                "inn": inn,
                "status": status,
                "csptest_name": cont,
                "thumbprint": thumb,
                "container_ok": cont_ok,
                "umy_pk": umy_pk,
                "sign_ok": sign_ok,
                "db_has_pk": c.has_private_key,
                "expired": expired,
                "detail": detail,
            }
            rows.append(row)
            mark = "OK" if status == "OK" else status
            self.stdout.write(
                f"[{i}/{len(inns)}] {inn} {mark} cont={cont_ok} umy_pk={umy_pk} sign={sign_ok or '-'} {detail[:100]}"
            )

        self.stdout.write("")
        self.stdout.write("=== СВОДКА ===")
        for k in sorted(stats.keys()):
            self.stdout.write(f"  {k}: {stats[k]}")

        bad = [r for r in rows if r["status"] not in ("OK", "WARN_EXPIRED")]
        if bad:
            self.stdout.write("")
            self.stdout.write("Проблемные ИНН:")
            for r in bad:
                self.stdout.write(f"  {r['inn']} {r['status']} — {r['detail'][:120]}")

        out_csv = (options["fix_csv"] or "").strip()
        if out_csv:
            with open(out_csv, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["inn"])
                w.writeheader()
                w.writerows(rows)
            self.stdout.write(f"CSV: {out_csv}")

        self.stdout.write("")
        self.stdout.write(
            "Починить FAIL_UMY: certmgr -inst -store uMy -file /tmp/<inn>.cer -cont \"<csptest_name>\""
        )
        self.stdout.write("Потом: python manage.py sync_has_private_key")
