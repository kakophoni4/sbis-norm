#!/usr/bin/env python3
import base64
import json
import sys
import uuid
import re
from datetime import datetime
from pathlib import Path

SRC_INN, SRC_KPP, SRC_NO = "9729337785", "773301001", "7733"
DST_INN, DST_KPP, DST_NO = "9707039440", "770701001", "7707"
SRC_IK, DST_IK = SRC_INN + SRC_KPP, DST_INN + DST_KPP
GUID_MAIN = "daaede5d-5b5c-4108-81c8-4f657906d85f"
GUID_8 = "48988d9e-a98b-4eea-b03e-63fd5ca787d3"
GUID_9 = "7f273f8e-c097-4a97-8793-ed9f59d922cc"

roots = [
    Path("/app/docs"),
    Path("/opt/sbis-norm/docs"),
    Path(__file__).resolve().parent,
]
root = None
for r in roots:
    if list(r.glob("NO_NDS_7733_7733_9729337785*.xml")):
        root = r
        break
if not root:
    sys.exit("sample xml not found")

main = next(root.glob("NO_NDS_7733_7733_9729337785*.xml"))
b8 = next(root.glob("NO_NDS_8_7733_7733_9729337785*.xml"))
b9 = next(root.glob("NO_NDS_9_7733_7733_9729337785*.xml"))
date_s = datetime.now().strftime("%Y%m%d")
g_main, g8, g9 = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())


def rw(t: str) -> str:
    t = re.sub(r'НаимОрг="[^"]*"', 'НаимОрг="ООО БАСТИОН"', t, count=1)
    t = t.replace(f'ИННЮЛ="{SRC_INN}"', f'ИННЮЛ="{DST_INN}"')
    t = t.replace(f'КПП="{SRC_KPP}"', f'КПП="{DST_KPP}"')
    t = t.replace(f"_{SRC_NO}_{SRC_NO}_", f"_{DST_NO}_{DST_NO}_")
    t = t.replace(SRC_IK, DST_IK)
    t = t.replace("_20260317_", f"_{date_s}_")
    t = t.replace(f'КодНО="{SRC_NO}"', f'КодНО="{DST_NO}"')
    t = re.sub(r'НомКорр="2"', 'НомКорр="99"', t)
    t = re.sub(r'ДатаДок="17\.03\.2026"', f'ДатаДок="{datetime.now().strftime("%d.%m.%Y")}"', t)
    t = t.replace(GUID_MAIN, g_main).replace(GUID_8, g8).replace(GUID_9, g9)
    return t


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


payload = {
    "inn": DST_INN,
    "main_xml_b64": b64(rw(main.read_bytes().decode("cp1251")).encode("cp1251")),
    "book_xml_b64_list": [
        b64(rw(b8.read_bytes().decode("cp1251")).encode("cp1251")),
        b64(rw(b9.read_bytes().decode("cp1251")).encode("cp1251")),
    ],
    "dry_run": False,
}
out = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/bastion_1c_payload.json")
out.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
print(out)
