#!/usr/bin/env python3
"""
Читает файл с выводом ls с сервера (строки — имена файлов в кавычках bash).
Группирует по ИНН (10 цифр), оставляет по одному самому свежему по дате.
Записывает в указанный файл только строки для удаления, с префиксом "rm ".

Использование:
  python server_ls_to_rm.py to_delete_list.txt
  (перезапишет to_delete_list.txt списком rm-команд для старых подписей)

Важно: перед запуском сохраните to_delete_list.txt с полным выводом ls с сервера.
"""
import re
import sys
from collections import defaultdict
from datetime import datetime


def parse_server_line(line: str):
    """Возвращает (raw_line, inn, date_key) или (raw_line, None, None)."""
    raw = line.strip()
    # Убираем уже стоящий впереди rm, чтобы не дублировать
    for prefix in ("rm -f ", "rm "):
        if raw.startswith(prefix):
            raw = raw[len(prefix):].strip()
            break
    # Пропускаем строки-приглашения
    if not raw or "devuser@" in raw or (raw.startswith("$") and "mega_signatures" in raw):
        return None
    # ИНН — 10 цифр подряд; дата — DD-MM-YY или DD-MM-YYYY (или с точкой) перед .rar/.zip/концом
    inn_match = re.search(r"(\d{10})\s+(\d{1,2})[-.](\d{1,2})[-.](\d{2,4})", raw)
    if not inn_match:
        return (raw, None, None)
    inn = inn_match.group(1)
    d, m, y = inn_match.group(2), inn_match.group(3), inn_match.group(4)
    try:
        if len(y) == 2:
            y = "20" + y if int(y) < 50 else "19" + y
        dt = datetime(int(y), int(m), int(d))
        date_key = dt.isoformat()
    except (ValueError, TypeError):
        date_key = None
    return (raw, inn, date_key)


def main():
    # Путь к файлу с выводом ls с сервера. Второй аргумент — куда писать (по умолчанию тот же файл).
    path = sys.argv[1] if len(sys.argv) > 1 else "to_delete_list.txt"
    out_path = sys.argv[2] if len(sys.argv) > 2 else path
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    by_inn = defaultdict(list)
    no_inn = []

    for line in lines:
        parsed = parse_server_line(line)
        if not parsed:
            continue
        raw_line, inn, date_key = parsed
        if not inn:
            no_inn.append(raw_line)
            continue
        by_inn[inn].append((raw_line, date_key))

    to_delete = []
    for inn, items in by_inn.items():
        items_sorted = sorted(
            items,
            key=lambda x: (x[1] or "0000-00-00"),
            reverse=True,
        )
        for raw_line, _ in items_sorted[1:]:
            to_delete.append(raw_line)

    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        for raw_line in sorted(to_delete):
            f.write("rm " + raw_line + "\n")

    print(f"Готово: в {out_path} записано {len(to_delete)} команд rm (удаляются только старые подписи).")


if __name__ == "__main__":
    main()
