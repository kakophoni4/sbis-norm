# -*- coding: utf-8 -*-
"""Сгенерировать curl для send-nds-extra-1c с ИНН 9729337785."""
import base64
import os

DOCS = os.path.dirname(os.path.abspath(__file__))
INN = "9729337785"
BASE_URL = "http://localhost:8000"

main_file = os.path.join(DOCS, "NO_NDS_7733_7733_9729337785773301001_20260317_daaede5d_5b5c_4108.xml")
book_files = [
    os.path.join(DOCS, "NO_NDS_8_7733_7733_9729337785773301001_20260317_48988d9e_a98b_4eea.xml"),
    os.path.join(DOCS, "NO_NDS_9_7733_7733_9729337785773301001_20260317_7f273f8e_c097_4a97.xml"),
]

def b64(path):
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")

main_b64 = b64(main_file)
book_b64_list = [b64(p) for p in book_files]

url = BASE_URL.rstrip("/") + "/api/sbis/send-nds-extra-1c/"
book_lines = []
for i, b in enumerate(book_b64_list):
    comma = "," if i < len(book_b64_list) - 1 else ""
    book_lines.append('      "' + b + '"' + comma)
book_block = "\n".join(book_lines)

curl_content = '''curl -i -X POST "''' + url + '''" \\
  -H "Content-Type: application/json" \\
  -d '{
    "inn": "''' + INN + '''",
    "main_xml_b64": "''' + main_b64 + '''",
    "book_xml_b64_list": [
''' + book_block + '''
    ]
  }'
'''

out_path = os.path.join(DOCS, "curl_9729337785.txt")
with open(out_path, "w", encoding="utf-8") as f:
    f.write(curl_content)
print("curl сохранён в:", out_path)
