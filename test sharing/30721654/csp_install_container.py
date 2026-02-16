#!/usr/bin/env python3
import argparse, os, shutil, subprocess, sys, pwd, re
from pathlib import Path

CSP_BIN  = "/opt/cprocsp/bin/amd64"
CSPTEST  = f"{CSP_BIN}/csptest"
CERTMGR  = f"{CSP_BIN}/certmgr"

def die(msg, code=1):
    print(f"ERROR: {msg}", file=sys.stderr); sys.exit(code)

def need_root():
    if os.geteuid() != 0:
        die("Запусти через sudo.")

def run(cmd, run_as=None):
    if run_as:
        cmd = ["sudo", "-u", run_as, "-H"] + cmd
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return r.returncode, (r.stdout or "")

def check_tools():
    for p in (CSPTEST, CERTMGR):
        if not (os.path.isfile(p) and os.access(p, os.X_OK)):
            die(f"Не найдена утилита: {p}")

def list_containers(user):
    rc, out = run([CSPTEST, "-keys", "-enum_cont", "-fqcn", "-verifyc"], run_as=user)
    # строки вида \\.\HDIMAGE\...
    return set(re.findall(r'\\\\\.\\HDIMAGE\\[^\r\n]+', out))

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
    dst = Path(f"/var/opt/cprocsp/keys/{user}/cont_{name}")  # ВАЖНО: cont_ prefix
    if dst.exists():
        if force: shutil.rmtree(dst)
        else: die(f"Каталог уже существует: {dst}. Используй --force или другое имя.")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst)
    pw = pwd.getpwnam(user)
    ensure_modes_owner(dst, pw.pw_uid, pw.pw_gid)
    return dst

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
    ap = argparse.ArgumentParser(description="Установка контейнера CryptoPro CSP (Linux)")
    ap.add_argument("-n", "--name", required=True, help="Имя для каталога (только для пути), напр. 30721654")
    ap.add_argument("-d", "--dir",  required=True, help="Каталог с ключами (header.key, primary.key, ...)")
    ap.add_argument("-u", "--user", default=os.environ.get("SUDO_USER") or os.environ.get("USER") or "root",
                    help="Пользователь, от имени которого контейнер будет использоваться")
    ap.add_argument("--force", action="store_true", help="Перезаписать каталог назначения")
    ap.add_argument("-c", "--cert", help="Путь к .cer/.crt/.der для установки в uMy (опционально)")
    ap.add_argument("-p", "--pin", default=None, help="PIN контейнера (если есть)")
    args = ap.parse_args()

    need_root(); check_tools()

    src  = Path(args.dir).expanduser().resolve()
    user = args.user
    name = args.name
    cert = Path(args.cert).expanduser().resolve() if args.cert else None

    if not src.is_dir(): die(f"Нет каталога: {src}")
    if not (src/"header.key").is_file(): die(f"Нет header.key в каталоге: {src}")
    if cert and not cert.is_file(): die(f"Нет файла сертификата: {cert}")

    before = list_containers(user)

    dst = copy_container(src, user, name, args.force)

    after = list_containers(user)
    added = sorted(after - before)
    if not added:
        # ничего нового не появилось — покажем, что есть
        print("Не обнаружен новый FQCN. Доступные контейнеры после копирования:")
        for c in sorted(after): print("  ", c)
        die("Контейнер не найден. Проверь, что путь назначения: " + str(dst))

    fqcn = added[0]
    print(f"[ok] Обнаружен контейнер: {fqcn}")

    if cert:
        install_cert(fqcn, cert, user, args.pin)
        print("[ok] Сертификат установлен в uMy.")

    print(f"[done] Готово. Контейнер: {fqcn}")

if __name__ == "__main__":
    main()
