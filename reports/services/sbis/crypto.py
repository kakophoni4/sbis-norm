import base64
import hashlib
import io
import json
import logging
import os
import random
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import requests
from django.conf import settings
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, ProxyError, SSLError, Timeout

from reports.models import Certificate
from reports.nodemaven_sdk.nodemaven import NodeMavenClient

from .constants import *

def _csp_use_sudo() -> bool:
    """Если True, certmgr/cryptcp запускаются через sudo (ключи в /var/opt/cprocsp/keys/root)."""
    return getattr(settings, "CSP_USE_SUDO", True)

def run_cmd(args: list[str], timeout_sec: int = 90) -> str:
    """Запуск команды без доступа к stdin. certmgr/cryptcp при CSP_USE_SUDO вызываются через sudo."""
    if args and args[0] in (CERTMGR_BIN, CRYPTCP_BIN) and _csp_use_sudo():
        args = ["sudo", *args]
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip() or f"exit code {result.returncode}"
            raise RuntimeError(f"{args[0] if args else '?'}: {err}")
        return result.stdout or ""
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(
            f"Команда {args[0] if args else '?'} не завершилась за {timeout_sec} с (возможен запрос пароля или недоступный контейнер)"
        ) from e

def export_cert_der(csptest_name: str, dest_path: str) -> None:
    run_cmd([CERTMGR_BIN, "-export", "-cont", csptest_name, "-dest", dest_path])

def get_certmgr_list_file_output(cert_path: str) -> str:
    """Полный текст `certmgr -list -file` (SHA1, Subject и т.д.)."""
    return run_cmd([CERTMGR_BIN, "-list", "-file", cert_path])

def get_thumbprint_from_cert(cert_path: str) -> str:
    return get_thumbprint_from_certmgr_listing(get_certmgr_list_file_output(cert_path))

def get_thumbprint_from_certmgr_listing(out: str) -> str:
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SHA1 Thumbprint"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1].strip().lower()
    raise RuntimeError("Не удалось вытащить SHA1 Thumbprint из файла сертификата")

def get_fio_from_cert_file(cert_path: str) -> str:
    """
    Из вывода certmgr -list -file извлечь ФИО (значение CN из Subject/Субъект).
    Нужно для СБИС.АутентифицироватьПоСертификату при запросе через прокси (обязательные поля Сертификат.ФИО, Сертификат.ИНН).
    """
    try:
        out = get_certmgr_list_file_output(cert_path)
    except Exception:
        return ""
    subject = ""
    for line in out.splitlines():
        line_stripped = line.strip()
        if line_stripped.startswith("Subject:") or line_stripped.startswith("Субъект:"):
            subject = line_stripped.split(":", 1)[1].strip()
            break
    if not subject:
        return ""
    m = re.search(r"CN=([^,]+)", subject, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r"CN\s*=\s*([^,]+)", subject, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return subject[:200].strip()


_KPP_SUBJECT_RES = (
    re.compile(r"(?i)\bKPP=([0-9]{9})\b"),
    re.compile(r"КПП=([0-9]{9})"),
    re.compile(r"1\.2\.643\.100\.5=([0-9]{9})\b"),
)


def parse_kpp_from_subject_text(text: str) -> str | None:
    """Ищет КПП в строке Subject / выводе certmgr."""
    if not (text or "").strip():
        return None
    for rx in _KPP_SUBJECT_RES:
        m = rx.search(text)
        if m:
            return m.group(1)
    return None

def parse_kpp_from_cert_file(
    cert_path: str,
    *,
    certmgr_listing: str | None = None,
) -> str | None:
    """
    Пытается извлечь 9-значный КПП из экспортированного .cer:
    openssl x509 -subject (DER/PEM), затем certmgr -list -file (или готовый текст в certmgr_listing).
    """
    blobs: list[str] = []

    openssl_bin = shutil.which("openssl")
    if openssl_bin and os.path.isfile(cert_path):
        for inform in ("DER", "PEM"):
            try:
                r = subprocess.run(
                    [openssl_bin, "x509", "-inform", inform, "-in", cert_path, "-noout", "-subject"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    stdin=subprocess.DEVNULL,
                )
                if r.returncode == 0 and (r.stdout or "").strip():
                    blobs.append(r.stdout.strip())
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                break

    if certmgr_listing is not None:
        blobs.append(certmgr_listing)
    else:
        try:
            blobs.append(
                run_cmd([CERTMGR_BIN, "-list", "-file", cert_path], timeout_sec=60)
            )
        except Exception:
            pass

    return parse_kpp_from_subject_text("\n".join(blobs))

def sign_xml_if_needed(xml_path: str, sign_path: str | None, thumbprint: str) -> str:
    if sign_path and os.path.exists(sign_path):
        return sign_path

    out_sign = f"{xml_path}.sgn"
    run_cmd([CRYPTCP_BIN, "-sign", "-detached", "-der", *CRYPTCP_SIGN_FLAGS, "-thumbprint", thumbprint, xml_path])

    if not os.path.exists(out_sign):
        raise RuntimeError(f"Не удалось создать подпись {out_sign}")
    return out_sign

def sbis_decrypt_bytes_with_cert_thumbprint(
    enc_bytes: bytes,
    *,
    thumbprint: str,
    inn: str = "no_inn",
    suffix: str = "sbis_dec",
) -> bytes:
    """
    Расшифровывает байты через cryptcp -decr -thumbprint <thumb>.
    СБИС шлёт зашифрованный файл — надо прогнать через закрытый ключ.
    """

    if not enc_bytes:
        raise RuntimeError("enc_bytes пустой")
    if not (thumbprint or "").strip():
        raise RuntimeError("thumbprint пустой")

    with tempfile.TemporaryDirectory(prefix=f"{suffix}_{inn}_") as td:
        enc_path = os.path.join(td, "in.enc")
        dec_path = os.path.join(td, "out.dec")

        with open(enc_path, "wb") as f:
            f.write(enc_bytes)

        run_cmd([CRYPTCP_BIN, "-decr", *CRYPTCP_DECR_FLAGS, "-thumbprint", thumbprint, enc_path, dec_path])

        out = Path(dec_path).read_bytes()
        return out

def _try_decrypt_bytes_with_cert(
    *,
    inn: str,
    thumbprint: str,
    content: bytes,
) -> tuple[bytes, dict]:
    """
    Пытается расшифровать content через cryptcp -decr.
    Если не получилось — вернет исходный content, но в meta будет decrypt_ok=False.
    """
    meta = {"decrypt_ok": False, "decrypt_error": None}

    if not content:
        return content, meta

    with tempfile.TemporaryDirectory(prefix=f"sbis_dec_{inn}_") as td:
        in_path = os.path.join(td, "in.bin")
        out_path = os.path.join(td, "out.bin")

        with open(in_path, "wb") as f:
            f.write(content)

        try:
            run_cmd([CRYPTCP_BIN, "-decr", *CRYPTCP_DECR_FLAGS, "-thumbprint", thumbprint, in_path, out_path])
            dec = Path(out_path).read_bytes()
            meta["decrypt_ok"] = True
            return dec, meta
        except Exception as e:
            meta["decrypt_error"] = str(e)
            return content, meta
