"""
Массовая отправка XML-отчётов ФНС из дерева папок Орг/Тип/*.xml.

Пример:
  docker compose exec -T web python manage.py send_reports_from_folder \\
    /app/media/otchetnost_2_26 --dry-run --limit 1

  docker compose exec -T web python manage.py send_reports_from_folder \\
    /app/media/otchetnost_2_26 --send --delay 7

Лимит СБИС: не более 10 ЗаписатьКомплект/мин
(https://saby.ru/help/integration/api/reporting) — поэтому --delay по умолчанию 7 с.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from reports.services.sbis.reports import (
    REPORT_TYPE_TO_KND,
    build_svedenia_from_report_xml,
    send_report,
)

# Имена подпапок (кириллица) → report_type
FOLDER_TYPE_MAP = {
    "ндс": "nds",
    "прибыль": "profit",
    "6ндфл": "ndfl6",
    "рсв": "rsv",
    "nds": "nds",
    "profit": "profit",
    "ndfl6": "ndfl6",
    "rsv": "rsv",
}


def _guess_type_from_folder(name: str) -> str | None:
    key = (name or "").strip().lower().replace(" ", "")
    return FOLDER_TYPE_MAP.get(key)


def _iter_xml_files(root: Path):
    """Орг/Тип/*.xml или просто **/*.xml."""
    for path in sorted(root.rglob("*.xml")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        parts = rel.parts
        org = parts[0] if len(parts) >= 2 else ""
        folder_type = parts[1] if len(parts) >= 3 else (parts[0] if len(parts) == 2 else "")
        yield path, org, folder_type


class Command(BaseCommand):
    help = "Отправить отчёты ФНС (НДС/Прибыль/6-НДФЛ/РСВ) из дерева папок через СБИС API"

    def add_arguments(self, parser):
        parser.add_argument("folder", type=str, help="Корневая папка (Орг/Тип/*.xml)")
        parser.add_argument("--dry-run", action="store_true", help="Только разбор XML, без отправки")
        parser.add_argument(
            "--send",
            action="store_true",
            help="Боевая отправка в СБИС (обязательно явно)",
        )
        parser.add_argument("--limit", type=int, default=0, help="Макс. число файлов (0 = все)")
        parser.add_argument(
            "--inns",
            type=str,
            default="",
            help="Фильтр ИНН через запятую (из XML)",
        )
        parser.add_argument(
            "--types",
            type=str,
            default="",
            help="Фильтр типов: nds,profit,ndfl6,rsv через запятую",
        )
        parser.add_argument(
            "--delay",
            type=float,
            default=7.0,
            help="Пауза между боевыми отправками, сек (лимит СБИС ≤10 ЗаписатьКомплект/мин)",
        )
        parser.add_argument(
            "--report-json",
            type=str,
            default="",
            help="Путь для JSON-отчёта о результатах",
        )

    def handle(self, *args, **options):
        folder = Path(options["folder"])
        if not folder.is_dir():
            raise CommandError(f"Папка не найдена: {folder}")

        dry_run = bool(options["dry_run"])
        do_send = bool(options["send"])
        if not dry_run and not do_send:
            raise CommandError("Укажите --dry-run или --send")
        if dry_run and do_send:
            raise CommandError("Нельзя одновременно --dry-run и --send")

        inns_filter = {x.strip() for x in (options["inns"] or "").split(",") if x.strip()}
        types_filter = {
            x.strip().lower() for x in (options["types"] or "").split(",") if x.strip()
        }
        for t in types_filter:
            if t not in REPORT_TYPE_TO_KND:
                raise CommandError(f"Неизвестный type={t}. Допустимо: {', '.join(sorted(REPORT_TYPE_TO_KND))}")

        limit = int(options["limit"] or 0)
        delay = max(0.0, float(options["delay"] or 0))

        results = []
        processed = 0

        for xml_path, org, folder_type in _iter_xml_files(folder):
            try:
                sved, our_org, kod_no, _po, guid, vers, meta = build_svedenia_from_report_xml(
                    str(xml_path), report_type="auto"
                )
            except Exception as e:
                row = {
                    "file": str(xml_path),
                    "org_folder": org,
                    "ok": False,
                    "error": f"parse: {e}",
                }
                results.append(row)
                self.stdout.write(self.style.ERROR(f"FAIL parse {xml_path}: {e}"))
                continue

            inn = ((our_org.get("СвЮЛ") or {}).get("ИНН") or "").strip()
            rtype = meta["report_type"]

            # уточнение по имени папки, если auto и папка известна
            folder_rtype = _guess_type_from_folder(folder_type)
            if folder_rtype and folder_rtype != rtype:
                self.stdout.write(
                    self.style.WARNING(
                        f"warn {xml_path.name}: папка={folder_rtype}, xml={rtype} — берём xml"
                    )
                )

            if inns_filter and inn not in inns_filter:
                continue
            if types_filter and rtype not in types_filter:
                continue

            processed += 1
            if limit and processed > limit:
                break

            self.stdout.write(
                f"[{processed}] {org}/{folder_type}/{xml_path.name} "
                f"inn={inn} type={rtype} knd={meta['knd']}"
            )

            if dry_run:
                row = {
                    "file": str(xml_path),
                    "org_folder": org,
                    "inn": inn,
                    "report_type": rtype,
                    "knd": meta["knd"],
                    "form_name": meta["form_name"],
                    "kod_no": kod_no,
                    "guid": guid,
                    "format_version": vers,
                    "ok": True,
                    "dry_run": True,
                }
                results.append(row)
                self.stdout.write(self.style.SUCCESS("  dry_run OK"))
                continue

            try:
                result = send_report(inn=inn, xml_path=str(xml_path), report_type=rtype)
            except Exception as e:
                msg = str(e)
                # Частые бизнес-ошибки СБИС (биллинг) — не traceback
                if any(
                    x in msg
                    for x in (
                        "нет лицензии",
                        "отправляете отчеты в долг",
                        "в долг",
                    )
                ):
                    result = {"success": False, "error": {"message": msg}}
                else:
                    result = {"success": False, "error": {"message": msg}}
                self.stdout.write(self.style.ERROR(f"  FAIL exception: {msg[:300]}"))

            ok = bool(isinstance(result, dict) and result.get("success"))
            send_meta = {}
            if ok:
                from reports.services.sbis.nds import _extract_send_meta_from_exec

                send_meta = _extract_send_meta_from_exec(result.get("result") or {})

            err = None if ok else (result.get("error") if isinstance(result, dict) else str(result))
            row = {
                "file": str(xml_path),
                "org_folder": org,
                "inn": inn,
                "report_type": rtype,
                "knd": meta["knd"],
                "ok": ok,
                "send_meta": send_meta,
                "error": err,
            }
            results.append(row)
            if ok:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"  OK sbis_doc_id={send_meta.get('sbis_doc_id')} sent_date={send_meta.get('sent_date')}"
                    )
                )
            else:
                self.stdout.write(self.style.ERROR(f"  FAIL {row['error']}"))

            if delay > 0:
                time.sleep(delay)

        ok_n = sum(1 for r in results if r.get("ok"))
        fail_n = len(results) - ok_n
        self.stdout.write("")
        self.stdout.write(f"Итого: {len(results)} файлов, ok={ok_n}, fail={fail_n}")

        out_path = (options.get("report_json") or "").strip()
        if out_path:
            Path(out_path).write_text(
                json.dumps({"results": results, "ok": ok_n, "fail": fail_n}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            self.stdout.write(f"JSON: {out_path}")
