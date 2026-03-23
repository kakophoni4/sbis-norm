"""
Расширение вложения требования по сырым байтам (после base64, из ZIP и т.д.).

Частый случай ФНС/СБИС: PKCS#7 / CMS (DER), OID 1.2.840.113549.1.7 — раньше помечался как .bin.
"""
from __future__ import annotations

# OID 1.2.840.113549.1.7 (pkcs-7 / CMS) в DER
PKCS7_ROOT_OID_DER = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07"


def guess_requirement_extension(data: bytes) -> str:
    if not data:
        return ".bin"
    if data.startswith(b"%PDF"):
        return ".pdf"
    st = data.lstrip()[:800]
    if st.startswith(b"<?xml") or st.startswith(b"<"):
        return ".xml"
    if data.startswith(b"\xef\xbb\xbf") and b"<" in data[:1200]:
        return ".xml"
    if data.startswith(b"\xff\xfe") and b"<" in data[:1200]:
        return ".xml"
    # Подпись/шифр ФНС в CMS — ищем OID в первых килобайтах
    if PKCS7_ROOT_OID_DER in data[:4096]:
        return ".p7m"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return ".zip"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return ".doc"
    return ".bin"


def sniff_kind_label(data: bytes) -> str:
    """Короткая метка для отчётов (inspect_requirement_file_types)."""
    if not data:
        return "пусто"
    ext = guess_requirement_extension(data)
    if ext == ".pdf":
        return "PDF"
    if ext == ".xml":
        return "XML_ASCII_или_UTF"
    if ext == ".p7m":
        return "PKCS7_CMS_p7m"
    if ext == ".zip":
        return "ZIP_PK"
    if ext == ".doc":
        return "OLE_DOC"
    return f"прочее_{data[:12].hex()}"
