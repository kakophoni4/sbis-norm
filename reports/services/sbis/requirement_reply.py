"""Ответ на требование ФНС: ЗаписатьКомплект (ПредставлениеФНС) → Подготовить → Выполнить."""
from __future__ import annotations

import base64
import json
import logging
import os
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

from reports.models import Certificate, Organization

from .auth import auth_sbis_by_cert
from .client import _sbis_request, log_http_exchange
from .constants import REPORTING_URL
from .crypto import export_cert_der, get_fio_from_cert_file, get_thumbprint_from_cert, sign_xml_if_needed

logger = logging.getLogger(__name__)

_SBIS_USER_AGENT = "sbis-norm/1.0 (requirement-reply; Django)"


def _clean_b64(s: str) -> str:
    s = (s or "").strip()
    if "," in s and "base64" in s[:100].lower():
        s = s.split(",", 1)[1].strip()
    s = "".join(s.split()).replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    return s


def _resolve_cert(inn: str) -> Certificate | None:
    return (
        Certificate.objects.filter(inn=inn, has_private_key=True, is_active=True)
        .exclude(csptest_name="")
        .exclude(csptest_name__isnull=True)
        .order_by("-id")
        .first()
    ) or Certificate.objects.filter(inn=inn).exclude(csptest_name="").order_by("-id").first()


def _our_org(inn: str, cert: Certificate) -> dict:
    org = Organization.objects.filter(inn=inn).first()
    kpp = ((cert.kpp or "") or (org.kpp if org else "") or "").strip()
    name = ((org.name if org else "") or f"ИНН {inn}").strip()
    return {"СвЮЛ": {"ИНН": inn, "КПП": kpp, "Название": name}}


def _normalize_attachments(attachments: list) -> list[dict]:
    out: list[dict] = []
    for i, item in enumerate(attachments or []):
        if not isinstance(item, dict):
            continue
        filename = (
            item.get("filename")
            or item.get("name")
            or item.get("file_name")
            or f"attachment_{i + 1}.bin"
        )
        filename = str(filename).strip() or f"attachment_{i + 1}.bin"
        # безопасность пути
        filename = Path(filename).name
        b64 = item.get("content_b64") or item.get("b64") or item.get("file_b64") or ""
        b64 = _clean_b64(str(b64))
        if not b64:
            continue
        try:
            raw = base64.b64decode(b64, validate=False)
        except Exception as e:
            raise ValueError(f"Некорректный base64 у {filename}: {e}") from e
        if not raw:
            continue
        out.append({"filename": filename, "content": raw})
    return out


def send_requirement_reply(
    inn: str,
    *,
    requirement_sbis_doc_id: str,
    attachments: list,
    dry_run: bool = False,
    org_name: str = "",
) -> dict:
    """
    Отправить ответ на требование (комплект документов) в СБИС.

    attachments: [{filename, content_b64}, ...]
    """
    inn = (inn or "").strip()
    requirement_sbis_doc_id = (requirement_sbis_doc_id or "").strip()
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if not requirement_sbis_doc_id:
        return {"success": False, "error": {"message": "requirement_sbis_doc_id обязателен"}}

    try:
        files = _normalize_attachments(attachments)
    except ValueError as e:
        return {"success": False, "error": {"message": str(e)}}
    if not files:
        return {"success": False, "error": {"message": "attachments[] обязателен (filename + content_b64)"}}

    cert = _resolve_cert(inn)
    if not cert:
        return {"success": False, "error": {"message": "Не найден сертификат для ИНН"}, "http_hint": 403}
    if not cert.csptest_name:
        return {"success": False, "error": {"message": "У ИНН нет валидной подписи (csptest_name)"}, "http_hint": 401}

    our_org = _our_org(inn, cert)
    if org_name:
        our_org["СвЮЛ"]["Название"] = org_name.strip()
    kpp = (our_org.get("СвЮЛ") or {}).get("КПП") or ""

    parsed = {
        "inn": inn,
        "requirement_sbis_doc_id": requirement_sbis_doc_id,
        "attachment_count": len(files),
        "filenames": [f["filename"] for f in files],
        "kpp": kpp,
        "org_name": (our_org.get("СвЮЛ") or {}).get("Название"),
    }
    if dry_run:
        return {
            "success": True,
            "comment": "DRY_RUN: вложения приняты, отправка в СБИС пропущена",
            "parsed": parsed,
        }

    cert_path = f"/tmp/sbis_req_reply_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)
    fio = (get_fio_from_cert_file(cert_path) or "—").strip() or "—"

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}"}}

    tmp_dir = tempfile.mkdtemp(prefix=f"req_reply_{inn}_")
    enclosures: list[dict] = []
    file_id_map: dict[str, str] = {}
    try:
        for f in files:
            path = os.path.join(tmp_dir, f["filename"])
            Path(path).write_bytes(f["content"])
            ident = str(uuid.uuid4())
            file_id_map[path] = ident
            try:
                sign_path = sign_xml_if_needed(path, None, thumbprint, csptest_name=cert.csptest_name)
            except Exception as e:
                return {"success": False, "error": {"message": f"Ошибка подписи {f['filename']}: {e}"}}
            with open(path, "rb") as fh:
                content_b64 = base64.b64encode(fh.read()).decode("ascii")
            with open(sign_path, "rb") as fh:
                sign_b64 = base64.b64encode(fh.read()).decode("ascii")
            enclosures.append(
                {
                    "Идентификатор": ident,
                    "Название": f["filename"],
                    "Категория": "Приложение",
                    "Файл": {
                        "Имя": f["filename"],
                        "ДвоичныеДанные": content_b64,
                        "Подпись": [{"ДвоичныеДанные": sign_b64}],
                    },
                }
            )

        reply_doc_id = str(uuid.uuid4())
        doc = {
            "Название": f"Ответ на требование ({requirement_sbis_doc_id[:8]})",
            "Идентификатор": reply_doc_id,
            "Тип": "ПредставлениеФНС",
            "ДатаВремяСоздания": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Расширение": {"ИдентификаторКомплекта": requirement_sbis_doc_id},
            "НашаОрганизация": our_org,
            "Вложение": enclosures,
            "Сертификат": {"Отпечаток": thumbprint, "Ключ": {"Тип": "Клиентский"}},
        }

        headers = {
            "Content-Type": "application/json-rpc;charset=utf-8",
            "X-SBISSessionID": session_id,
            "User-Agent": _SBIS_USER_AGENT,
        }

        body = {"jsonrpc": "2.0", "method": "СБИС.ЗаписатьКомплект", "params": {"Документ": [doc]}, "id": 1}
        body_json = json.dumps(body, ensure_ascii=False)
        resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=body_json, timeout=60)
        log_http_exchange("REQ_REPLY_WRITE", REPORTING_URL, headers, body_json, resp)

        if resp.status_code != 200:
            return {
                "success": False,
                "error": {"message": f"HTTP {resp.status_code} ЗаписатьКомплект", "raw": (resp.text or "")[:800]},
            }
        try:
            data = resp.json()
        except Exception as e:
            return {"success": False, "error": {"message": f"JSON ЗаписатьКомплект: {e}", "raw": (resp.text or "")[:400]}}
        if data.get("error"):
            return {"success": False, "error": data["error"]}

        result_list = data.get("result")
        if isinstance(result_list, list) and result_list:
            written = result_list[0] if isinstance(result_list[0], dict) else {}
        elif isinstance(result_list, dict):
            written = result_list
        else:
            written = {}
        sbis_doc_id = (written.get("Идентификатор") or reply_doc_id).strip()

        # Этап/действие из ответа или дефолт Отправка/Отправить
        stage_name = "Отправка"
        action_name = "Отправить"
        stages = written.get("Этап") or []
        if isinstance(stages, dict):
            stages = [stages]
        if stages and isinstance(stages[0], dict):
            st0 = stages[0]
            if st0.get("Название"):
                stage_name = str(st0.get("Название")).strip() or stage_name
            actions = st0.get("Действие") or []
            if isinstance(actions, dict):
                actions = [actions]
            for a in actions:
                if isinstance(a, dict) and a.get("Название"):
                    action_name = str(a.get("Название")).strip() or action_name
                    break

        prep_body = {
            "jsonrpc": "2.0",
            "method": "СБИС.ПодготовитьДействие",
            "params": {
                "Документ": {
                    "Идентификатор": sbis_doc_id,
                    "Этап": {
                        "Название": stage_name,
                        "Действие": {
                            "Название": action_name,
                            "Сертификат": {"Отпечаток": thumbprint},
                        },
                    },
                }
            },
            "id": 2,
        }
        prep_json = json.dumps(prep_body, ensure_ascii=False)
        prep_resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=prep_json, timeout=60)
        log_http_exchange("REQ_REPLY_PREP", REPORTING_URL, headers, prep_json, prep_resp)
        if prep_resp.status_code != 200:
            return {
                "success": False,
                "error": {"message": f"HTTP {prep_resp.status_code} ПодготовитьДействие", "raw": (prep_resp.text or "")[:800]},
                "reply_sbis_doc_id": sbis_doc_id,
            }
        try:
            prep_data = prep_resp.json()
        except Exception as e:
            return {"success": False, "error": {"message": f"JSON ПодготовитьДействие: {e}"}, "reply_sbis_doc_id": sbis_doc_id}
        if prep_data.get("error"):
            return {"success": False, "error": prep_data["error"], "reply_sbis_doc_id": sbis_doc_id}

        exec_attachments = []
        for path, ident in file_id_map.items():
            sig_path = f"{path}.sgn"
            try:
                sign_xml_if_needed(path, None, thumbprint, csptest_name=cert.csptest_name)
                with open(sig_path, "rb") as fh:
                    sig_b64 = base64.b64encode(fh.read()).decode("ascii")
                exec_attachments.append(
                    {"Идентификатор": ident, "Подпись": [{"Файл": {"ДвоичныеДанные": sig_b64}}]}
                )
            except Exception as e:
                return {
                    "success": False,
                    "error": {"message": f"Ошибка подписи для execute {os.path.basename(path)}: {e}"},
                    "reply_sbis_doc_id": sbis_doc_id,
                }

        exec_body = {
            "jsonrpc": "2.0",
            "method": "СБИС.ВыполнитьДействие",
            "params": {
                "Документ": {
                    "Идентификатор": sbis_doc_id,
                    "Этап": {
                        "Название": stage_name,
                        "Действие": {
                            "Название": action_name,
                            "Сертификат": {"Отпечаток": thumbprint, "ИНН": inn, "ФИО": fio},
                        },
                        "Вложение": exec_attachments,
                    },
                }
            },
            "id": 3,
        }
        exec_json = json.dumps(exec_body, ensure_ascii=False)
        exec_resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=exec_json, timeout=90)
        log_http_exchange("REQ_REPLY_EXEC", REPORTING_URL, headers, exec_json, exec_resp)
        if exec_resp.status_code != 200:
            return {
                "success": False,
                "error": {"message": f"HTTP {exec_resp.status_code} ВыполнитьДействие", "raw": (exec_resp.text or "")[:800]},
                "reply_sbis_doc_id": sbis_doc_id,
            }
        try:
            exec_data = exec_resp.json()
        except Exception as e:
            return {"success": False, "error": {"message": f"JSON ВыполнитьДействие: {e}"}, "reply_sbis_doc_id": sbis_doc_id}
        if exec_data.get("error"):
            return {"success": False, "error": exec_data["error"], "reply_sbis_doc_id": sbis_doc_id}

        sent_at = datetime.now()
        return {
            "success": True,
            "result": exec_data.get("result") or exec_data,
            "send_meta": {
                "reply_sbis_doc_id": sbis_doc_id,
                "requirement_sbis_doc_id": requirement_sbis_doc_id,
                "stage_name": stage_name,
                "action_name": action_name,
                "sent_at": sent_at.isoformat(timespec="seconds"),
                "sent_date": sent_at.strftime("%Y-%m-%d"),
                "filenames": [f["filename"] for f in files],
            },
            "parsed": parsed,
        }
    finally:
        try:
            for name in os.listdir(tmp_dir):
                try:
                    os.remove(os.path.join(tmp_dir, name))
                except Exception:
                    pass
            os.rmdir(tmp_dir)
        except Exception:
            pass
