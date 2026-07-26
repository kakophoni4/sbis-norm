import hashlib
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path

from rest_framework.response import Response
from rest_framework.views import APIView

from reports.services.sbis import send_report_1c

logger = logging.getLogger(__name__)

ONEC_LOG_DIR = Path("/home/devuser/sbis_api_logs/1c_in")
ONEC_LOG_DIR.mkdir(parents=True, exist_ok=True)


def _clean_b64(s: str) -> str:
    s = (s or "").strip()
    if "," in s and "base64" in s[:100].lower():
        s = s.split(",", 1)[1].strip()
    s = "".join(s.split()).replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    return s


class SendReport1CView(APIView):
    """
    POST /api/sbis/send-report-1c/
    Новый эндпоинт для НДС/Прибыль/6-НДФЛ/РСВ (один XML).
    Не заменяет send-nds-extra-1c (НДС с книгами для 1С).
    """

    permission_classes = []

    def post(self, request, *args, **kwargs):
        inn = str(request.data.get("inn", "")).strip()
        xml_b64 = (
            request.data.get("xml_b64")
            or request.data.get("main_xml_b64")
            or request.data.get("main_b64")
        )
        report_type = str(request.data.get("report_type", "auto") or "auto").strip().lower()

        if not inn or not xml_b64:
            return Response(
                {
                    "success": False,
                    "comment": "Ошибка входных данных",
                    "error": {"message": "Поля inn и xml_b64 обязательны"},
                },
                status=400,
            )

        dry_val = request.data.get("dry_run", False)
        dry_run = (
            dry_val.strip().lower() in ("1", "true", "yes", "y", "on")
            if isinstance(dry_val, str)
            else bool(dry_val)
        )

        self._log_payload(inn=inn, xml_b64=xml_b64, report_type=report_type, dry_run=dry_run)
        status_code, body = send_report_1c(
            inn=inn,
            xml_b64=xml_b64,
            report_type=report_type,
            dry_run=dry_run,
        )
        return Response(body, status=status_code)

    def _log_payload(self, inn, xml_b64, report_type, dry_run):
        try:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            rid = uuid.uuid4().hex[:8]
            base = ONEC_LOG_DIR / f"{ts}_{inn or 'no_inn'}_report_{rid}"
            base.mkdir(parents=True, exist_ok=True)
            clean = _clean_b64(str(xml_b64 or ""))
            (base / "report.b64").write_text(clean, encoding="utf-8")
            meta = {
                "inn": inn,
                "report_type": report_type,
                "dry_run": dry_run,
                "b64_sha256": hashlib.sha256(clean.encode("utf-8", errors="ignore")).hexdigest(),
            }
            (base / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
            logger.info("[1C_IN_REPORT] saved payload to: %s", base)
        except Exception:
            logger.exception("[1C_IN_REPORT] failed to log payload")
