#!/usr/bin/env python3
"""
Читает вывод листинга папки mega_signatures (строки вида "F /path/to/file.rar"),
группирует по ИНН (10 цифр в имени), оставляет по одному самому свежему файлу по дате,
печатает команды rm для удаления остальных (старых).

Использование:
  python mega_keep_newest_signatures.py < listing_7707.txt
  python mega_keep_newest_signatures.py --keep listing_7707.txt   # вывести только список оставляемых
  python mega_keep_newest_signatures.py --dry-run listing_7707.txt  # только показать, что удалить/оставить
"""
import re
import sys
from collections import defaultdict
from datetime import datetime


def parse_line(line: str):
    """Возвращает (path, inn, date_key) или (path, inn, None) если дату не удалось извлечь."""
    line = line.strip()
    if not line.startswith("F ") or "/" not in line:
        return None
    path = line[2:].strip()
    # ИНН — 10 цифр подряд (в именах ключей это всегда ИНН)
    inns = re.findall(r"[0-9]{10}", path)
    inn = inns[0] if inns else None
    if not inn:
        return (path, None, None)
    # Дата: DD-MM-YYYY, DD-MM-YY, DD.MM.YY, DD.MM.YYYY перед .rar/.zip или конец имени
    date_match = re.search(
        r"(\d{1,2})[-.](\d{1,2})[-.](\d{2,4})(?:\s|\)|\.rar|\.zip|$)",
        path,
        re.IGNORECASE,
    )
    if not date_match:
        return (path, inn, None)
    d, m, y = date_match.group(1), date_match.group(2), date_match.group(3)
    try:
        if len(y) == 2:
            y = "20" + y if int(y) < 50 else "19" + y
        dt = datetime(int(y), int(m), int(d))
        date_key = dt.isoformat()
    except (ValueError, TypeError):
        date_key = None
    return (path, inn, date_key)


def main():
    mode = "delete"  # delete | keep | dry-run
    if len(sys.argv) >= 2:
        if sys.argv[1] == "--keep":
            mode = "keep"
            argv = sys.argv[2:]
        elif sys.argv[1] == "--dry-run":
            mode = "dry-run"
            argv = sys.argv[2:]
        else:
            argv = sys.argv[1:]
    else:
        argv = []

    if argv:
        lines = open(argv[0], "r", encoding="utf-8", errors="replace").readlines()
    else:
        lines = sys.stdin.readlines()

    by_inn = defaultdict(list)
    no_inn = []

    for line in lines:
        parsed = parse_line(line)
        if not parsed:
            continue
        path, inn, date_key = parsed
        if not inn:
            no_inn.append(path)
            continue
        by_inn[inn].append((path, date_key))

    # По каждому ИНН оставляем один файл — с максимальной датой (None считаем старым)
    to_keep = []
    to_delete = []

    for inn, items in by_inn.items():
        # Сортируем: с датой вперёд, по дате по убыванию; без даты в конец
        items_sorted = sorted(
            items,
            key=lambda x: (x[1] is None, -(ord(x[1][0]) if x[1] else 0)),
        )
        # Проще: сортировать по date_key (None меньше любого)
        def sort_key(item):
            path, dk = item
            return (dk is None, dk or "")

        items_sorted = sorted(items, key=sort_key)
        # Новейший — последний (максимальная дата)
        items_sorted = sorted(
            items,
            key=lambda x: (x[1] or "0000-00-00"),
            reverse=True,
        )
        to_keep.append(items_sorted[0][0])
        for path, _ in items_sorted[1:]:
            to_delete.append(path)

    # Файлы без ИНН не трогаем (не удаляем)
    to_keep.extend(no_inn)

    if mode == "keep":
        for p in sorted(to_keep):
            print(p)
        return

    if mode == "dry-run":
        print("=== Оставить (по одному новейшему на ИНН) ===")
        for p in sorted(to_keep):
            print(p)
        print("\n=== Удалить (старые дубликаты по ИНН) ===")
        for p in sorted(to_delete):
            print(p)
        print(f"\nВсего оставить: {len(to_keep)}, удалить: {len(to_delete)}")
        return

    # mode == "delete" — команды rm для выполнения на сервере
    print("# Удалить старые подписи (оставить только самые свежие по ИНН). Выполнять на сервере в каталоге с mega_signatures.")
    print("# Количество файлов к удалению:", len(to_delete))
    print()
    for path in sorted(to_delete):
        # Экранируем путь для bash
        path_esc = path.replace("'", "'\"'\"'")
        print(f"rm -f '{path_esc}'")


if __name__ == "__main__":
    main()
