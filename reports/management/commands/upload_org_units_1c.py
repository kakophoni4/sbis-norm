"""
Загрузка организаций в 1С (HTTP-сервис mole /units).

Проверка auth:
  python manage.py upload_org_units_1c --health-only

Загрузка из CSV collect_org_data:
  python manage.py upload_org_units_1c \\
    --from-csv /app/media/org_export/organizations_FINAL_670_v2.csv \\
    --batch-size 25 --delay 2

Переменные окружения (app.env):
  ONE_C_MOLE_BASE_URL=http://45.142.193.159/demo/hs/mole
  ONE_C_MOLE_USER=mole
  ONE_C_MOLE_PASSWORD=...
"""
from __future__ import annotations

import csv
import json
import time
from pathlib import Path

from django.core.management.base import BaseCommand

from reports.management.commands.collect_org_data import EXPORT_COLUMNS
from reports.services.onec_mole import mole_health, mole_upload_units


def _load_rows(path: Path) -> list[dict]:
    rows = list(csv.DictReader(path.open(encoding="utf-8-sig")))
    out: list[dict] = []
    for row in rows:
        item = {col: (row.get(col) or "").strip() for col in EXPORT_COLUMNS if col in row}
        if not item.get("ИНН"):
            inn = (row.get("ИНН") or row.get("inn") or "").strip()
            if inn:
                item["ИНН"] = inn
        if item.get("ИНН"):
            out.append(item)
    return out


def _chunks(items: list[dict], size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


class Command(BaseCommand):
    help = "Загрузить организации в 1С (mole/units) пакетами"

    def add_arguments(self, parser):
        parser.add_argument(
            "--from-csv",
            default="",
            help="CSV из collect_org_data (organizations_*.csv)",
        )
        parser.add_argument(
            "--from-json",
            default="",
            help="JSON-массив организаций (альтернатива CSV)",
        )
        parser.add_argument("--batch-size", type=int, default=25)
        parser.add_argument("--delay", type=float, default=2.0, help="Пауза между пакетами, сек")
        parser.add_argument("--limit", type=int, default=0)
        parser.add_argument("--offset", type=int, default=0)
        parser.add_argument("--health-only", action="store_true")
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--skip-health", action="store_true")

    def handle(self, *args, **options):
        if not options["health_only"]:
            rows = self._load_input(options)
            if options["offset"]:
                rows = rows[options["offset"] :]
            if options["limit"]:
                rows = rows[: options["limit"]]
        else:
            rows = []

        if not options["skip_health"] or options["health_only"]:
            self.stdout.write("Проверка GET /health ...")
            try:
                code, body = mole_health()
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"health failed: {e}"))
                raise SystemExit(1) from e
            self.stdout.write(f"  HTTP {code}")
            self.stdout.write(f"  {body[:500]}")
            if code < 200 or code >= 300:
                self.stdout.write(self.style.ERROR("health не OK — загрузку не начинаем"))
                raise SystemExit(1)
            self.stdout.write(self.style.SUCCESS("health OK"))
            if options["health_only"]:
                return

        if not rows:
            self.stdout.write(self.style.ERROR("Нет данных для загрузки (--from-csv / --from-json)"))
            raise SystemExit(1)

        batch_size = max(1, int(options["batch_size"]))
        delay = max(0.0, float(options["delay"]))
        batches = list(_chunks(rows, batch_size))
        self.stdout.write(f"К загрузке: {len(rows)} организаций, пакетов: {len(batches)} (по {batch_size})")

        if options["dry_run"]:
            self.stdout.write(self.style.WARNING("DRY RUN — POST не отправляется"))
            self.stdout.write(json.dumps(rows[:2], ensure_ascii=False, indent=2))
            return

        ok_batches = 0
        for i, batch in enumerate(batches, start=1):
            inns = ", ".join(r["ИНН"] for r in batch[:3])
            if len(batch) > 3:
                inns += f", ... (+{len(batch) - 3})"
            self.stdout.write(f"[{i}/{len(batches)}] POST {len(batch)} шт. ({inns})")
            try:
                code, body = mole_upload_units(batch)
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  ошибка сети: {e}"))
                raise SystemExit(1) from e

            preview = (body or "").replace("\n", " ")[:300]
            self.stdout.write(f"  HTTP {code}: {preview}")
            if code < 200 or code >= 300:
                self.stdout.write(self.style.ERROR("  пакет отклонён — остановка"))
                raise SystemExit(1)
            ok_batches += 1
            if i < len(batches) and delay > 0:
                time.sleep(delay)

        self.stdout.write(self.style.SUCCESS(f"Готово: {len(rows)} организаций, {ok_batches} пакетов"))

    def _load_input(self, options) -> list[dict]:
        if options.get("from_json"):
            path = Path(options["from_json"])
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
            raise SystemExit("JSON должен быть массивом объектов")
        if options.get("from_csv"):
            path = Path(options["from_csv"])
            if not path.is_file():
                raise SystemExit(f"Файл не найден: {path}")
            return _load_rows(path)
        raise SystemExit("Укажите --from-csv или --from-json")
