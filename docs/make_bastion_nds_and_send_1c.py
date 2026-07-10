# -*- coding: utf-8 -*-
"""
На СЕРВЕРЕ (/opt/sbis-norm): собрать XML под БАСТИОН и прогнать через HTTP API 1С.

  cd /opt/sbis-norm
  python3 docs/make_bastion_nds_and_send_1c.py --dry-run
  python3 docs/make_bastion_nds_and_send_1c.py --send

Ищет sample в docs/ или sbis-norm/docs/. Бьёт в http://127.0.0.1:8000 (как 1С).
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import uuid
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
CANDIDATE_ROOTS = [
    HERE,
    HERE.parent / "sbis-norm" / "docs",
    Path("/app/docs"),
    Path("/app/sbis-norm/docs"),
    Path("/opt/sbis-norm/docs"),
    Path("/opt/sbis-norm/sbis-norm/docs"),
]

SRC_INN = "9729337785"
SRC_KPP = "773301001"
SRC_NO = "7733"
SRC_INN_KPP = f"{SRC_INN}{SRC_KPP}"

DST_INN = "9707039440"
DST_KPP = "770701001"
DST_NO = "7707"
DST_INN_KPP = f"{DST_INN}{DST_KPP}"
DST_NAME = "ООО БАСТИОН"

GUID_MAIN_OLD = "daaede5d-5b5c-4108-81c8-4f657906d85f"
GUID_8_OLD = "48988d9e-a98b-4eea-b03e-63fd5ca787d3"
GUID_9_OLD = "7f273f8e-c097-4a97-8793-ed9f59d922cc"


def find_samples() -> tuple[Path, Path, Path]:
    for root in CANDIDATE_ROOTS:
        if not root.is_dir():
            continue
        mains = list(root.glob("NO_NDS_7733_7733_9729337785*.xml"))
        b8s = list(root.glob("NO_NDS_8_7733_7733_9729337785*.xml"))
        b9s = list(root.glob("NO_NDS_9_7733_7733_9729337785*.xml"))
        if mains and b8s and b9s:
            return mains[0], b8s[0], b9s[0]
    raise SystemExit("не найден sample NO_NDS_*9729337785*.xml")


def rewrite(text: str, *, date_s: str, g_main: str, g8: str, g9: str) -> str:
    t = text
    t = re.sub(r'НаимОрг="[^"]*"', f'НаимОрг="{DST_NAME}"', t, count=1)
    t = t.replace(f'ИННЮЛ="{SRC_INN}"', f'ИННЮЛ="{DST_INN}"')
    t = t.replace(f'КПП="{SRC_KPP}"', f'КПП="{DST_KPP}"')
    t = t.replace(f"_{SRC_NO}_{SRC_NO}_", f"_{DST_NO}_{DST_NO}_")
    t = t.replace(SRC_INN_KPP, DST_INN_KPP)
    t = t.replace("_20260317_", f"_{date_s}_")
    t = t.replace(f'КодНО="{SRC_NO}"', f'КодНО="{DST_NO}"')
    t = re.sub(r'НомКорр="2"', 'НомКорр="99"', t)
    t = re.sub(r'ДатаДок="17\.03\.2026"', f'ДатаДок="{datetime.now().strftime("%d.%m.%Y")}"', t)
    t = t.replace(GUID_MAIN_OLD, g_main)
    t = t.replace(GUID_8_OLD, g8)
    t = t.replace(GUID_9_OLD, g9)
    if DST_INN not in t or DST_KPP not in t:
        raise RuntimeError("rewrite incomplete: INN/KPP")
    return t


def build_files(out_dir: Path) -> tuple[Path, Path, Path]:
    src_main, src_b8, src_b9 = find_samples()
    print("sample from:", src_main.parent)
    out_dir.mkdir(parents=True, exist_ok=True)
    date_s = datetime.now().strftime("%Y%m%d")
    g_main, g8, g9 = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())

    main_t = rewrite(src_main.read_bytes().decode("cp1251"), date_s=date_s, g_main=g_main, g8=g8, g9=g9)
    b8_t = rewrite(src_b8.read_bytes().decode("cp1251"), date_s=date_s, g_main=g_main, g8=g8, g9=g9)
    b9_t = rewrite(src_b9.read_bytes().decode("cp1251"), date_s=date_s, g_main=g_main, g8=g8, g9=g9)

    main_p = out_dir / f"NO_NDS_{DST_NO}_{DST_NO}_{DST_INN_KPP}_{date_s}_{g_main.replace('-', '_')}.xml"
    b8_p = out_dir / f"NO_NDS_8_{DST_NO}_{DST_NO}_{DST_INN_KPP}_{date_s}_{g8.replace('-', '_')}.xml"
    b9_p = out_dir / f"NO_NDS_9_{DST_NO}_{DST_NO}_{DST_INN_KPP}_{date_s}_{g9.replace('-', '_')}.xml"
    main_p.write_bytes(main_t.encode("cp1251"))
    b8_p.write_bytes(b8_t.encode("cp1251"))
    b9_p.write_bytes(b9_t.encode("cp1251"))
    print("written:", main_p.name, b8_p.name, b9_p.name)
    return main_p, b8_p, b9_p


def b64(p: Path) -> str:
    return base64.b64encode(p.read_bytes()).decode("ascii")


def http_post(url: str, payload: dict, timeout: int = 600):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--out-dir", default="")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--send", action="store_true")
    args = ap.parse_args()
    if not args.dry_run and not args.send:
        args.dry_run = True

    out_dir = Path(args.out_dir) if args.out_dir else (HERE / "bastion_nds_1c_test")
    main_p, b8_p, b9_p = build_files(out_dir)

    base = args.base_url.rstrip("/")
    send_url = f"{base}/api/sbis/send-nds-extra-1c/"
    receipt_url = f"{base}/api/sbis/get-receipt-pdf-1c/"
    payload = {
        "inn": DST_INN,
        "main_xml_b64": b64(main_p),
        "book_xml_b64_list": [b64(b8_p), b64(b9_p)],
    }

    print("\n=== DRY_RUN", send_url, "===")
    code, body = http_post(send_url, {**payload, "dry_run": True})
    print("HTTP", code)
    print(json.dumps(body, ensure_ascii=False, indent=2)[:3000] if isinstance(body, dict) else body)
    if code != 200 or not (isinstance(body, dict) and body.get("success")):
        return 1
    if args.dry_run and not args.send:
        print("\nOK dry_run. Дальше: python3 docs/make_bastion_nds_and_send_1c.py --send")
        return 0

    print("\n=== REAL SEND", send_url, "===")
    code, body = http_post(send_url, {**payload, "dry_run": False})
    print("HTTP", code)
    print(json.dumps(body, ensure_ascii=False, indent=2)[:5000] if isinstance(body, dict) else body)
    (out_dir / "last_send_response.json").write_text(
        json.dumps(body, ensure_ascii=False, indent=2) if isinstance(body, dict) else str(body),
        encoding="utf-8",
    )
    if not (isinstance(body, dict) and body.get("success")):
        return 2

    meta = body.get("send_meta") or {}
    print("send_meta:", meta)
    doc_id, sent_date = meta.get("sbis_doc_id"), meta.get("sent_date")
    if doc_id and sent_date:
        print("\n=== RECEIPT", receipt_url, "===")
        rcode, rbody = http_post(
            receipt_url, {"inn": DST_INN, "sbis_doc_id": doc_id, "sent_date": sent_date}
        )
        print("HTTP", rcode)
        if isinstance(rbody, dict):
            preview = {
                k: (v[:60] + "…" if k == "pdf_b64" and isinstance(v, str) and len(v) > 60 else v)
                for k, v in rbody.items()
            }
            print(json.dumps(preview, ensure_ascii=False, indent=2)[:2500])
            (out_dir / "last_receipt_response.json").write_text(
                json.dumps(rbody, ensure_ascii=False, indent=2), encoding="utf-8"
            )
    print("\nDONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
