#!/usr/bin/env python3
import argparse, subprocess, sys, re
from pathlib import Path

CSPTEST = "/opt/cprocsp/bin/amd64/csptest"

def run(cmd, run_as=None):
    if run_as:
        cmd = ["sudo", "-u", run_as, "-H"] + cmd
    p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, (p.stdout or "")

def list_containers(user):
    rc, out = run([CSPTEST, "-keys", "-enum_cont", "-fqcn", "-verifyc"], run_as=user)
    return [line.strip() for line in out.splitlines() if "\\\\.\\HDIMAGE\\" in line or "\\.\\HDIMAGE\\" in line]

def extract_guids_from_name_key(path: Path):
    b = path.read_bytes()
    guids = set(re.findall(rb'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}', b))
    return [g.decode('ascii') for g in guids]

def main():
    ap = argparse.ArgumentParser(description="Определить FQCN контейнера по name.key и списку CSP")
    ap.add_argument("-d", "--dir", required=True, help="Каталог контейнера (где лежит name.key)")
    ap.add_argument("-u", "--user", default=None, help="Пользователь (для csptest). Обычно devuser.")
    args = ap.parse_args()

    cont_dir = Path(args.dir).expanduser().resolve()
    name_key = cont_dir / "name.key"
    if not name_key.is_file():
        print(f"ERROR: name.key не найден: {name_key}", file=sys.stderr)
        sys.exit(1)

    guids = extract_guids_from_name_key(name_key)
    if not guids:
        print("Не удалось извлечь GUID из name.key.", file=sys.stderr)
        sys.exit(2)

    guid = guids[0]
    conts = list_containers(args.user)

    print("Контейнеры (csptest):")
    for c in conts:
        print(" ", c)

    print(f"\nGUID из name.key: {guid}")

    # Ищем совпадения по GUID
    matches = [c for c in conts if guid.lower() in c.lower()]
    if matches:
        print("\nСовпадения по GUID:")
        for m in matches:
            print(" ", m)
        # Если одно совпадение — считаем это точным именем
        if len(matches) == 1:
            print(f"\nТочный FQCN: {matches[0]}")
            sys.exit(0)
        else:
            print("\nНесколько совпадений. Выбери нужный из списка выше.")
            sys.exit(0)
    else:
        # Подсказываем вероятные варианты
        print("\nСовпадений не найдено в выводе csptest.")
        print("Вероятные варианты имени (если контейнер ещё не подхватился):")
        print(f"  \\\\.\\HDIMAGE\\{guid}")
        print(f"  \\\\.\\HDIMAGE\\{guid} копия")
        sys.exit(3)

if __name__ == "__main__":
    main()
