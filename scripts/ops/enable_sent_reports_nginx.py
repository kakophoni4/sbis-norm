"""Run as root on SBIS host AFTER deploying web. Only change known API location.

No stream/VPN edits. Back up outside sites-enabled, validate, reload.
Unknown configuration is rejected before writing anything.
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def transform(text):
    pattern = re.compile(r"location\s+~\s+\^/api/sbis/\(([^\n]+)\)/\$\s*\{")
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise ValueError("Expected exactly one SBIS whitelist location; inspect nginx manually")
    match = matches[0]
    routes = match.group(1).split("|")
    known = {"send-nds-extra-1c", "send-report-1c", "report-statuses-1c",
             "sent-reports-1c", "sent-report-xml-1c"}
    if set(routes) - known or not {"send-nds-extra-1c", "send-report-1c", "report-statuses-1c"} <= set(routes):
        raise ValueError("Unexpected whitelist; refusing automatic edit")
    # Find matching brace, accounting for the nested method check.
    depth, end = 1, match.end()
    while end < len(text) and depth:
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
        end += 1
    if depth:
        raise ValueError("Unbalanced location")
    body = text[match.end():end - 1]
    if "proxy_pass http://127.0.0.1:8000;" not in body:
        raise ValueError("Unexpected upstream; refusing automatic edit")
    for route in ("sent-reports-1c", "sent-report-xml-1c"):
        if route not in routes:
            routes.append(route)
    timeout = re.compile(r"proxy_read_timeout\s+[^;]+;")
    if len(timeout.findall(body)) > 1:
        raise ValueError("Multiple timeouts")
    if timeout.search(body):
        body = timeout.sub("proxy_read_timeout 180s;", body)
    else:
        body = "\n        proxy_read_timeout 180s;" + body
    opening = "location ~ ^/api/sbis/(" + "|".join(routes) + ")/$ {"
    return text[:match.start()] + opening + body + text[end - 1:]


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run as root")
    path = Path("/etc/nginx/sites-enabled/01-crmkanasha-ssl").resolve(strict=True)
    if not path.is_file() or Path("/etc/nginx") not in path.parents:
        raise SystemExit("Unexpected nginx target")
    subprocess.run(["nginx", "-t"], check=True)
    original = path.read_text(encoding="utf-8")
    updated = transform(original)
    if updated == original:
        print("Nginx already configured; no changes")
        return
    backup = Path(tempfile.mkdtemp(prefix="sbis-sent-api-nginx-", dir="/root"))
    shutil.copy2(path, backup / "config")
    print("Backup:", backup, flush=True)
    try:
        path.write_text(updated, encoding="utf-8")
        subprocess.run(["nginx", "-t"], check=True)
        subprocess.run(["systemctl", "reload", "nginx"], check=True)
    except BaseException:
        shutil.copy2(backup / "config", path)
        subprocess.run(["nginx", "-t"], check=True)
        subprocess.run(["systemctl", "reload", "nginx"], check=True)
        raise
    print("API whitelist updated; stream/VPN configuration was not changed")


if __name__ == "__main__":
    main()
