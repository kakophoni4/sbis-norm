"""
Отправка пакетов НДС (NO_NDS + NO_NDS.8 + NO_NDS.9) из дерева папок.

Ожидаемая структура (как в 11.08.zip):
  Корневая/
    Глория/NO_NDS_....xml
    Глория/NO_NDS.8_....xml
    Глория/NO_NDS.9_....xml
    ...

Пример:
  docker compose exec -T web python manage.py send_nds_packages_from_folder \\
    /app/media/11.08 --dry-run

  docker compose exec -T web python manage.py send_nds_packages_from_folder \\
    /app/media/11.08 --send --delay 7
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from reports.services.sbis.nds import send_nds_extra

_MAIN_RE = re.compile(r"^NO_NDS_\d", re.IGNORECASE)
_BOOK8_RE = re.compile(r"^NO_NDS\.8_", re.IGNORECASE)
_BOOK9_RE = re.compile(r"^NO_NDS\.9_", re.IGNORECASE)


def _pick_one(files: list[Path], pred) -> Path | None:
    hits = [p for p in files if pred(p.name)]
    if not hits:
        return None
    return sorted(hits, key=lambda p: p.name)[0]


def _discover_packages(root: Path) -> list[dict]:
    """
    Ищем пакеты:
      - в подпапках организации (Org/*.xml)
      - или плоско в корне, группируя по ИНН из имени файла
    """
    packages: list[dict] = []

    subdirs = [p for p in sorted(root.iterdir()) if p.is_dir()]
    if subdirs:
        for d in subdirs:
            xmls = sorted(d.glob("*.xml"))
            if not xmls:
                continue
            main = _pick_one(xmls, lambda n: _MAIN_RE.match(n) and not n.upper().startswith("NO_NDS.8") and not n.upper().startswith("NO_NDS.9"))
            # NO_NDS_ vs NO_NDS.8_ — MAIN_RE is NO_NDS_\d which won't match NO_NDS.8_
            book8 = _pick_one(xmls, lambda n: _BOOK8_RE.match(n))
            book9 = _pick_one(xmls, lambda n: _BOOK9_RE.match(n))
            packages.append(
                {
                    "org": d.name,
                    "dir": d,
                    "main": main,
                    "book8": book8,
                    "book9": book9,
                }
            )
        return packages

    # плоский каталог
    xmls = sorted(root.glob("*.xml"))
    by_key: dict[str, list[Path]] = {}
    for p in xmls:
        # ключ — хвост после префикса книги, до даты: ...ИННКПП_YYYYMMDD_uuid
        m = re.search(r"(NO_NDS(?:\.\d)?_)(.+)$", p.name, re.I)
        key = (m.group(2) if m else p.stem)
        # нормализуем: у .8/.9 тот же суффикс после префикса почти совпадает по ИНН+дате
        m2 = re.search(r"_(\d{10,12}\d{9})_(\d{8})_", p.name)
        if m2:
            key = f"{m2.group(1)}_{m2.group(2)}"
        by_key.setdefault(key, []).append(p)

    for key, group in sorted(by_key.items()):
        main = _pick_one(group, lambda n: _MAIN_RE.match(n))
        book8 = _pick_one(group, lambda n: _BOOK8_RE.match(n))
        book9 = _pick_one(group, lambda n: _BOOK9_RE.match(n))
        packages.append(
            {
                "org": key,
                "dir": root,
                "main": main,
                "book8": book8,
                "book9": book9,
            }
        )
    return packages


def _inn_from_main_name(name: str) -> str | None:
    # NO_NDS_7731_7731_9731112362773101001_20260811_uuid.xml
    m = re.search(r"NO_NDS_\d+_\d+_(\d{10})", name, re.I)
    return m.group(1) if m else None


class Command(BaseCommand):
    help = "Отправить пакеты НДС (NO_NDS + .8 + .9) из папок организаций"

    def add_arguments(self, parser):
        parser.add_argument("folder", type=str, help="Корень с папками организаций")
        parser.add_argument("--dry-run", action="store_true", help="Только проверка пакетов")
        parser.add_argument("--send", action="store_true", help="Боевая отправка в СБИС")
        parser.add_argument("--limit", type=int, default=0, help="Макс. число пакетов (0=все)")
        parser.add_argument("--inns", type=str, default="", help="Фильтр ИНН через запятую")
        parser.add_argument(
            "--delay",
            type=float,
            default=7.0,
            help="Пауза между отправками, сек (лимит СБИС ≤10/мин)",
        )
        parser.add_argument(
            "--report-json",
            type=str,
            default="",
            help="Куда сохранить JSON-отчёт",
        )
        parser.add_argument(
            "--title-prefix",
            type=str,
            default="Доп.листы книги продаж",
            help="Префикс названия документа в СБИС",
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
        limit = int(options["limit"] or 0)
        delay = max(0.0, float(options["delay"] or 0))
        title_prefix = (options["title_prefix"] or "").strip() or "Доп.листы книги продаж"

        packages = _discover_packages(folder)
        if not packages:
            raise CommandError(f"Пакеты NO_NDS не найдены в {folder}")

        results = []
        processed = 0
        for pkg in packages:
            main: Path | None = pkg["main"]
            book8: Path | None = pkg["book8"]
            book9: Path | None = pkg["book9"]
            org = pkg["org"]

            if not main:
                row = {"org": org, "ok": False, "error": "нет основного NO_NDS_*.xml"}
                results.append(row)
                self.stdout.write(self.style.ERROR(f"FAIL {org}: нет NO_NDS_*.xml"))
                continue

            inn = _inn_from_main_name(main.name) or ""
            if inns_filter and inn not in inns_filter:
                continue

            processed += 1
            if limit and processed > limit:
                break

            books = [p for p in (book8, book9) if p is not None]
            self.stdout.write(
                f"[{processed}] {org} inn={inn or '?'} "
                f"main={main.name} books={[b.name for b in books]}"
            )

            if dry_run:
                missing = []
                if book8 is None:
                    missing.append("NO_NDS.8")
                if book9 is None:
                    missing.append("NO_NDS.9")
                row = {
                    "org": org,
                    "inn": inn,
                    "main": str(main),
                    "book8": str(book8) if book8 else None,
                    "book9": str(book9) if book9 else None,
                    "ok": True,
                    "dry_run": True,
                    "warn_missing_books": missing or None,
                }
                results.append(row)
                msg = "  dry_run OK"
                if missing:
                    msg += f" (нет {', '.join(missing)})"
                self.stdout.write(self.style.SUCCESS(msg))
                continue

            if not inn:
                row = {"org": org, "ok": False, "error": f"не удалось взять ИНН из {main.name}"}
                results.append(row)
                self.stdout.write(self.style.ERROR(f"  FAIL: нет ИНН в имени {main.name}"))
                continue

            try:
                result = send_nds_extra(
                    inn=inn,
                    xml_path=str(main),
                    book_paths=[str(b) for b in books],
                    doc_title_prefix=title_prefix,
                )
            except Exception as e:
                result = {"success": False, "error": {"message": str(e)}}

            ok = bool(isinstance(result, dict) and result.get("success"))
            err = None if ok else (result.get("error") if isinstance(result, dict) else str(result))
            row = {
                "org": org,
                "inn": inn,
                "main": str(main),
                "books": [str(b) for b in books],
                "ok": ok,
                "error": err,
                "result_keys": sorted((result or {}).keys()) if isinstance(result, dict) else None,
            }
            if ok:
                send_meta = result.get("send_meta") or {}
                if not send_meta and isinstance(result.get("result"), dict):
                    from reports.services.sbis.nds import _extract_send_meta_from_exec

                    send_meta = _extract_send_meta_from_exec(result.get("result") or {})
                row["send_meta"] = send_meta
                self.stdout.write(
                    self.style.SUCCESS(
                        f"  OK doc={send_meta.get('sbis_doc_id') or send_meta.get('Идентификатор') or '?'}"
                    )
                )
            else:
                msg = err.get("message") if isinstance(err, dict) else str(err)
                self.stdout.write(self.style.ERROR(f"  FAIL: {str(msg)[:300]}"))
            results.append(row)

            if delay and processed < len(packages):
                time.sleep(delay)

        ok_n = sum(1 for r in results if r.get("ok"))
        err_n = len(results) - ok_n
        self.stdout.write(self.style.SUCCESS(f"Готово: ok={ok_n} err={err_n} total={len(results)}"))

        report_path = (options["report_json"] or "").strip()
        if report_path:
            Path(report_path).write_text(
                json.dumps(results, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
            self.stdout.write(f"report: {report_path}")
