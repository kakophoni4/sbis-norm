#!/usr/bin/env python3
import argparse, os, shutil, subprocess, sys, pwd, re
from pathlib import Path

CSP_BIN = "/opt/cprocsp/bin/amd64"
CSPTEST = f"{CSP_BIN}/csptest"
CERTMGR = f"{CSP_BIN}/certmgr"

def die(msg, code=1):
    print(f"ERROR: {msg}", file=sys.stderr); sys.exit(code)

def run(cmd, run_as=None):
    if run_as:
        cmd = ["sudo", "-u", run_as, "-H"] + cmd
    p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, (p.stdout or "")

def need_root():
    if os.geteuid() != 0:
        die("Запусти через sudo.")

def check_tools():
    for p in (CSPTEST, CERTMGR):
        if not (os.path.isfile(p) and os.access(p, os.X_OK)):
            die(f"Не найдена утилита: {p}")

def ensure_modes_owner(path: Path, uid: int, gid: int):
    for root, dirs, files in os.walk(path):
        for d in dirs:
            p = Path(root) / d
            try: os.chmod(p, 0o700); os.chown(p, uid, gid)
            except Exception: pass
        for f in files:
            p = Path(root) / f
            try: os.chmod(p, 0o600); os.chown(p, uid, gid)
            except Exception: pass
    try: os.chmod(path, 0o700); os.chown(path, uid, gid)
    except Exception: pass

def copy_container(src: Path, user: str, name: str, force: bool) -> Path:
    # ВАЖНО: префикс cont_
    dst = Path(f"/var/opt/cprocsp/keys/{user}/cont_{name}")
    if dst.exists():
        if force: shutil.rmtree(dst)
        else: die(f"Каталог уже существует: {dst}. Используй --force.")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst)
    pw = pwd.getpwnam(user)
    ensure_modes_owner(dst, pw.pw_uid, pw.pw_gid)
    return dst

def list_fqcn(user: str):
    rc, out = run([CSPTEST, "-keys", "-enum_cont", "-fqcn", "-verifyc"], run_as=user)
    # Ловим строки с \\.\HDIMAGE\...
    conts = []
    for line in out.splitlines():
        if "\\\\.\\HDIMAGE\\" in line or "\\.\\HDIMAGE\\" in line:
            conts.append(line.strip())
    return set(conts), out

def import_with_addcont(path: Path, user: str):
    # Важно: импортируем от лица пользователя, который будет работать с контейнером
    rc, out = run([CSPTEST, "-addcont", "-dir", str(path), "-pass", ""], run_as=user)
    # csptest может вернуть не-0 даже при добавлении; не валим процесс, просто показываем вывод
    print(out)

def install_cert(fqcn: str, cert: Path, user: str, pin: str|None):
    cmd = [CERTMGR, "-install", "-store", "uMy", "-cont", fqcn, "-file", str(cert)]
    if pin: cmd += ["-pin", pin]
    rc, out = run(cmd, run_as=user)
    print(out)
    if rc != 0:
        die("Не удалось установить сертификат в uMy.")
    rc, out = run([CERTMGR, "-list", "-cont", fqcn], run_as=user)
    print(out)

def main():
    ap = argparse.ArgumentParser(description="Установка контейнера CryptoPro CSP (Linux): copy -> addcont -> имя -> (cert)")
    ap.add_argument("-n", "--name", required=True, help="Имя для каталога (только для пути), напр. 30721654")
    ap.add_argument("-d", "--dir",  required=True, help="Каталог с ключами (header.key, primary.key, ...)")
    ap.add_argument("-u", "--user", default=os.environ.get("SUDO_USER") or os.environ.get("USER") or "root",
                    help="Пользователь, который будет использовать контейнер")
    ap.add_argument("--force", action="store_true", help="Перезаписать каталог назначения")
    ap.add_argument("-c", "--cert", help="Путь к .cer/.crt/.der (опционально)")
    ap.add_argument("-p", "--pin",  default=None, help="PIN контейнера (если есть)")
    args = ap.parse_args()

    need_root(); check_tools()

    src  = Path(args.dir).expanduser().resolve()
    user = args.user
    name = args.name
    cert = Path(args.cert).expanduser().resolve() if args.cert else None

    if not src.is_dir(): die(f"Нет каталога: {src}")
    if not (src/"header.key").is_file(): die(f"Нет header.key в каталоге: {src}")
    if cert and not cert.is_file(): die(f"Нет файла сертификата: {cert}")

    print("[1/4] Список контейнеров ДО:")
    before, out_before = list_fqcn(user)
    if out_before.strip(): print(out_before)

    print("[2/4] Копирую в системное хранилище...")
    dst = copy_container(src, user, name, args.force)
    print(f" -> {dst}")

    print("[3/4] Импортирую контейнер (csptest -addcont -dir ...)...")
    import_with_addcont(dst, user)

    print("[4/4] Список контейнеров ПОСЛЕ:")
    after, out_after = list_fqcn(user)
    if out_after.strip(): print(out_after)

    added = sorted(after - before)
    if not added:
        print("Не обнаружен новый FQCN (возможно, был импортирован ранее).")
        # Покажем подсказку, как может называться FQCN
        print("Подсказка: чаще всего имя берётся из name.key, и выглядит как GUID + 'копия'.")
        print("Примеры: \\\\.\\HDIMAGE\\<GUID> или \\\\.\\HDIMAGE\\<GUID> копия")
        die(f"Проверь существующие контейнеры выше. Путь контейнера: {dst}")

    # Если добавился ровно один — это наше имя
    fqcn = added[0]
    print(f"[OK] Контейнер добавлен: {fqcn}")

    if cert:
        print("[cert] Устанавливаю сертификат в uMy...")
        install_cert(fqcn, cert, user, args.pin)
        print("[cert] Готово.")

    print(f"[DONE] Имя контейнера (FQCN): {fqcn}")

if __name__ == "__main__":
    main()
