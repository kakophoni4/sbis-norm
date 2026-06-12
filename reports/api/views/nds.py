import hashlib
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from reports.services.sbis import (
    fetch_receipt_pdf_b64_from_archive,
    fetch_sales_book_extract_by_counterparty,
    send_nds_extra,
    send_nds_extra_1c,
)

logger = logging.getLogger(__name__)

UPLOAD_DIR = Path("/tmp/sbis_uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
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


def _sha256_text(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8", errors="ignore")).hexdigest()


class SendNdsExtraView(APIView):
    def post(self, request, *args, **kwargs):
        inn = str(request.data.get("inn", "")).strip()
        xml_file = request.FILES.get("xml_file")
        book_files = request.FILES.getlist("book_files")

        if not inn or not xml_file:
            return Response({"detail": "Поля inn и xml_file обязательны"}, status=status.HTTP_400_BAD_REQUEST)

        xml_path = str(UPLOAD_DIR / xml_file.name)
        with open(xml_path, "wb") as f:
            for chunk in xml_file.chunks():
                f.write(chunk)

        book_paths = []
        for bf in book_files:
            book_path = str(UPLOAD_DIR / bf.name)
            with open(book_path, "wb") as f:
                for chunk in bf.chunks():
                    f.write(chunk)
            book_paths.append(book_path)

        result = send_nds_extra(inn=inn, xml_path=xml_path, sign_path=None, book_paths=book_paths)
        return Response(result, status=status.HTTP_200_OK)


class SendNdsExtra1CView(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        inn = str(request.data.get("inn", "")).strip()
        main_xml_b64 = request.data.get("main_xml_b64") or request.data.get("xml_b64") or request.data.get("main_b64")
        book_list = request.data.get("book_xml_b64_list") or request.data.get("books_b64") or request.data.get("book_b64_list") or []

        if isinstance(book_list, list) and book_list and isinstance(book_list[0], dict):
            book_list = [(b.get("b64") or b.get("content_b64") or "").strip() for b in book_list]

        if not inn or not main_xml_b64:
            return Response(
                {"success": False, "comment": "Ошибка входных данных", "error": {"message": "Поля inn и main_xml_b64 обязательны"}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not isinstance(book_list, list):
            return Response(
                {"success": False, "comment": "Ошибка входных данных", "error": {"message": "book_xml_b64_list должен быть списком"}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        dry_val = request.data.get("dry_run", False)
        dry_run = dry_val.strip().lower() in ("1", "true", "yes", "y", "on") if isinstance(dry_val, str) else bool(dry_val)

        self._log_1c_payload(inn=inn, main_xml_b64=main_xml_b64, book_list=book_list, dry_run=dry_run, request=request)
        status_code, body = send_nds_extra_1c(inn=inn, main_xml_b64=main_xml_b64, book_xml_b64_list=book_list, dry_run=dry_run)
        return Response(body, status=status_code)

    def _log_1c_payload(self, inn, main_xml_b64, book_list, dry_run, request):
        try:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            rid = uuid.uuid4().hex[:8]
            base = ONEC_LOG_DIR / f"{ts}_{inn or 'no_inn'}_{rid}"
            base.mkdir(parents=True, exist_ok=True)
            main_clean = _clean_b64(str(main_xml_b64 or ""))
            main_b64_path = base / "main.b64"
            main_b64_path.write_text(main_clean, encoding="utf-8")
            books_meta = []
            for i, b in enumerate(book_list or [], start=1):
                b_clean = _clean_b64(str(b or ""))
                p = base / f"book_{i}.b64"
                p.write_text(b_clean, encoding="utf-8")
                books_meta.append({"i": i, "path": str(p)})
            meta = {"inn": inn, "dry_run": dry_run, "books": books_meta}
            (base / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
            logger.info(f"[1C_IN] saved payload to: {base}")
        except Exception as e:
            logger.exception(f"[1C_IN] failed to log payload: {e}")


class GetSalesBookExtractView(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        inn = str(request.data.get("inn", "")).strip()
        if not inn:
            return Response(
                {"success": False, "comment": "Ошибка входных данных", "error": {"message": "Поле inn обязательно"}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            max_docs = max(1, min(50, int(request.data.get("max_docs", 30))))
            rpc_timeout_sec = max(8, min(60, int(request.data.get("rpc_timeout_sec", 25))))
            rpc_budget_sec = max(12, min(90, int(request.data.get("rpc_budget_sec", 30))))
            archive_timeout_sec = max(8, min(60, int(request.data.get("archive_timeout_sec", 20))))
            archive_budget_sec = max(12, min(90, int(request.data.get("archive_budget_sec", 25))))
            auth_timeout_sec = max(8, min(45, int(request.data.get("auth_timeout_sec", 14))))
            auth_budget_sec = max(12, min(90, int(request.data.get("auth_budget_sec", 20))))
            proxy_prewarm_count = max(1, min(10, int(request.data.get("proxy_prewarm_count", 6))))
        except Exception:
            return Response(
                {"success": False, "comment": "Ошибка входных данных", "error": {"message": "Числовые поля некорректны"}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        result = fetch_sales_book_extract_by_counterparty(
            inn=inn,
            counterparty_id=str(request.data.get("counterparty_id", "")).strip() or None,
            date_from=str(request.data.get("date_from", "")).strip() or None,
            date_to=str(request.data.get("date_to", "")).strip() or None,
            sbis_doc_id=str(request.data.get("sbis_doc_id", "")).strip() or None,
            nds_subtype=str(request.data.get("nds_subtype", "")).strip() or None,
            max_docs=max_docs,
            rpc_timeout_sec=rpc_timeout_sec,
            rpc_budget_sec=rpc_budget_sec,
            archive_timeout_sec=archive_timeout_sec,
            archive_budget_sec=archive_budget_sec,
            auth_timeout_sec=auth_timeout_sec,
            auth_budget_sec=auth_budget_sec,
            proxy_prewarm_count=proxy_prewarm_count,
        )
        code = status.HTTP_200_OK if result.get("success") else status.HTTP_400_BAD_REQUEST
        return Response(result, status=code)


class GetReceiptPdfFromArchive1CView(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        inn = str(request.data.get("inn", "")).strip()
        sbis_doc_id = str(request.data.get("sbis_doc_id", "")).strip()
        sent_date = str(request.data.get("sent_date", "")).strip()
        if not inn or not sbis_doc_id or not sent_date:
            return Response(
                {"success": False, "comment": "Ошибка входных данных", "error": {"message": "Поля inn, sbis_doc_id, sent_date обязательны"}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        result = fetch_receipt_pdf_b64_from_archive(inn=inn, sbis_doc_id=sbis_doc_id, sent_date=sent_date)
        code = status.HTTP_200_OK if result.get("success") else status.HTTP_400_BAD_REQUEST
        return Response(result, status=code)
