#!/usr/bin/env python3
import sys, shutil, subprocess
from pathlib import Path

MEGA_URL = 'https://mega.nz/folder/k1UE0IxQ#YZIpbOp2Wcxt4HnPKHLViw'

def main():
    dest = Path(__file__).resolve().parent  # куда качать: рядом со скриптом
    mega_get = shutil.which('mega-get')
    if not mega_get:
        print('mega-get не найден. Установите MEGAcmd: sudo apt install megacmd или sudo snap install megacmd --classic', file=sys.stderr)
        sys.exit(1)

    print(f'Скачивание в: {dest}')
    try:
        # ВАЖНО: без -o, локальный путь вторым аргументом
        subprocess.run([mega_get, MEGA_URL, str(dest)], check=True)
        print('Готово.')
    except subprocess.CalledProcessError as e:
        print(f'Ошибка MEGAcmd: {e}', file=sys.stderr)
        sys.exit(e.returncode)

if __name__ == '__main__':
    main()
