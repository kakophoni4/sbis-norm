import base64
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, date as date_type, timedelta
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from pydantic import ValidationError
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import (
    Certificate,
    Document,
    EventLog,
    MailCache,
    Organization,
    Recipient,
    ReportType,
)
from .sbis_service import send_nds_extra, send_nds_extra_1c, fetch_receipt_pdf_b64_from_archive
from .schemas import MailLookupRequest, MailLookupResponse, SubmitReportSchema
from .serializers import DocumentCreateSerializer, DocumentStatusSerializer
from .tasks import schedule_mail_fetch, start_report_processing_chain

logger = logging.getLogger(__name__)

UPLOAD_DIR = Path("/tmp/sbis_uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ONEC_LOG_DIR = Path("/home/devuser/sbis_api_logs/1c_in")
ONEC_LOG_DIR.mkdir(parents=True, exist_ok=True)


def _clean_b64(s: str) -> str:
    s = (s or "").strip()
    if "," in s and "base64" in s[:100].lower():
        s = s.split(",", 1)[1].strip()
    s = "".join(s.split())
    s = s.replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    return s


def _sha256_text(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8", errors="ignore")).hexdigest()


class SubmitReportView(APIView):
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        try:
            schema = SubmitReportSchema(**request.data)
        except ValidationError as e:
            return Response(e.errors(), status=status.HTTP_400_BAD_REQUEST)

        organization, _ = Organization.objects.get_or_create(
            inn=schema.inn,
            defaults={"name": f"Организация с ИНН {schema.inn}"},
        )
        report_type, _ = ReportType.objects.get_or_create(
            code=schema.report_type,
            defaults={"name": schema.form_name or "Неизвестный тип", "format_version": "N/A"},
        )
        recipient, _ = Recipient.objects.get_or_create(
            code=schema.tax_office_code,
            defaults={"name": f"Получатель с кодом {schema.tax_office_code}"},
        )

        file_paths = []
        checksums_for_db = []
        doc_uuid = Document().id
        storage_dir = os.path.join(settings.MEDIA_ROOT, str(doc_uuid))
        os.makedirs(storage_dir, exist_ok=True)

        for file_data in schema.files:
            try:
                file_content = base64.b64decode(file_data.base64_string)
                file_path = os.path.join(storage_dir, file_data.name)
                with open(file_path, "wb") as f:
                    f.write(file_content)
                file_paths.append(os.path.relpath(file_path, settings.MEDIA_ROOT))
                checksums_for_db.append(file_data.checksum)
            except (ValueError, TypeError):
                return Response(
                    {"error": f"Некорректный формат base64 для файла '{file_data.name}'."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        svedeniya = {
            "Описание": {
                "ВидДокумента": "первичный",
                "ИмяФормы": schema.form_name,
                "КНДФормы": report_type.code,
                "КолФайл": len(schema.files),
                "Период": [{"Год": schema.year, "Код": schema.period_code}],
            },
            "Пакет": {"ВерсПрог": "API Integration 1.0"},
        }

        document = Document.objects.create(
            id=doc_uuid,
            organization=organization,
            report_type=report_type,
            recipient=recipient,
            files=file_paths,
            checksum=checksums_for_db,
            theme=schema.theme,
            svedeniya=svedeniya,
            status=Document.Status.PENDING,
        )

        EventLog.objects.create(
            document=document,
            event_type=EventLog.EventType.SIGN,
            details={"message": "Документ принят и поставлен в очередь на обработку."},
        )

        start_report_processing_chain(document.id)

        serializer = DocumentCreateSerializer(document)
        return Response(serializer.data, status=status.HTTP_202_ACCEPTED)


class ReportStatusView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Document.objects.all()
    serializer_class = DocumentStatusSerializer
    lookup_field = "id"


class WebhookTestView(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        logger.info(f"Получен тестовый вебхук. Тело запроса: {request.data}")
        return Response({"status": "ok"}, status=status.HTTP_200_OK)


class MailLookupView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            payload = MailLookupRequest(**request.data)
        except ValidationError as exc:
            return Response(exc.errors(), status=status.HTTP_400_BAD_REQUEST)

        logger.info(f"Запрос почты для ИНН {payload.inn} за дату {payload.requested_date}")

        cache_entry = MailCache.objects.filter(
            inn=payload.inn,
            period_date=payload.requested_date,
        ).first()

        if cache_entry:
            cache_age = (timezone.now() - cache_entry.retrieved_at).total_seconds()
            if cache_age < 3600:
                resp = MailLookupResponse(
                    inn=payload.inn,
                    requested_date=payload.requested_date,
                    status="FOUND",
                    email=cache_entry.email,
                    attachments=cache_entry.attachments_meta if payload.include_attachments else None,
                    message="Данные найдены в локальном кеше.",
                )
                return Response(resp.dict(), status=status.HTTP_200_OK)

        cert = Certificate.objects.filter(inn=payload.inn, is_active=True).first()
        if not cert:
            resp = MailLookupResponse(
                inn=payload.inn,
                requested_date=payload.requested_date,
                status="ERROR",
                message="Сертификат для данного ИНН не найден. Требуется установка.",
                email=None,
                attachments=None,
            )
            return Response(resp.dict(), status=status.HTTP_404_NOT_FOUND)

        try:
            result = schedule_mail_fetch(
                inn=payload.inn,
                requested_date=payload.requested_date,
                include_attachments=payload.include_attachments,
            )

            job_id = result.id if hasattr(result, "id") else str(result)

            resp = MailLookupResponse(
                inn=payload.inn,
                requested_date=payload.requested_date,
                status="PENDING",
                job_id=job_id,
                message="Задача на получение почты запущена. Повторите запрос через несколько секунд.",
                email=None,
                attachments=None,
            )
            return Response(resp.dict(), status=status.HTTP_202_ACCEPTED)

        except Exception as e:
            logger.exception(f"Ошибка при запуске задачи получения почты: {e}")
            resp = MailLookupResponse(
                inn=payload.inn,
                requested_date=payload.requested_date,
                status="ERROR",
                message=f"Ошибка при запуске задачи: {str(e)}",
                email=None,
                attachments=None,
            )
            return Response(resp.dict(), status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SendNdsExtraView(APIView):
    def post(self, request, *args, **kwargs):
        inn = str(request.data.get("inn", "")).strip()
        xml_file = request.FILES.get("xml_file")
        book_files = request.FILES.getlist("book_files")

        if not inn or not xml_file:
            return Response(
                {"detail": "Поля inn и xml_file обязательны"},
                status=status.HTTP_400_BAD_REQUEST,
            )

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

        result = send_nds_extra(
            inn=inn,
            xml_path=xml_path,
            sign_path=None,
            book_paths=book_paths,
        )
        return Response(result, status=status.HTTP_200_OK)


class SendNdsExtra1CView(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        inn = str(request.data.get("inn", "")).strip()

        main_xml_b64 = (
            request.data.get("main_xml_b64")
            or request.data.get("xml_b64")
            or request.data.get("main_b64")
        )

        book_list = (
            request.data.get("book_xml_b64_list")
            or request.data.get("books_b64")
            or request.data.get("book_b64_list")
            or []
        )

        if isinstance(book_list, list) and book_list and isinstance(book_list[0], dict):
            book_list = [(b.get("b64") or b.get("content_b64") or "").strip() for b in book_list]

        if not inn or not main_xml_b64:
            return Response(
                {
                    "success": False,
                    "comment": "Ошибка входных данных",
                    "error": {"message": "Поля inn и main_xml_b64 обязательны"},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not isinstance(book_list, list):
            return Response(
                {
                    "success": False,
                    "comment": "Ошибка входных данных",
                    "error": {"message": "book_xml_b64_list должен быть списком"},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        dry_val = request.data.get("dry_run", False)
        if isinstance(dry_val, str):
            dry_run = dry_val.strip().lower() in ("1", "true", "yes", "y", "on")
        else:
            dry_run = bool(dry_val)

        self._log_1c_payload(inn=inn, main_xml_b64=main_xml_b64, book_list=book_list, dry_run=dry_run, request=request)

        status_code, body = send_nds_extra_1c(
            inn=inn,
            main_xml_b64=main_xml_b64,
            book_xml_b64_list=book_list,
            dry_run=dry_run,
        )
        return Response(body, status=status_code)

    def _log_1c_payload(self, inn: str, main_xml_b64, book_list, dry_run: bool, request):
        try:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            rid = uuid.uuid4().hex[:8]
            inn_for_log = inn or "no_inn"

            base = ONEC_LOG_DIR / f"{ts}_{inn_for_log}_{rid}"
            base.mkdir(parents=True, exist_ok=True)

            main_raw = str(main_xml_b64 or "")
            main_clean = _clean_b64(main_raw)
            main_b64_path = base / "main.b64"
            main_b64_path.write_text(main_clean, encoding="utf-8")

            books_meta = []
            for i, b in enumerate(book_list or [], start=1):
                b_raw = str(b or "")
                b_clean = _clean_b64(b_raw)
                p = base / f"book_{i}.b64"
                p.write_text(b_clean, encoding="utf-8")
                books_meta.append(
                    {
                        "i": i,
                        "len_clean": len(b_clean),
                        "sha256_clean": _sha256_text(b_clean) if b_clean else None,
                        "path": str(p),
                    }
                )

            meta = {
                "inn": inn,
                "dry_run": dry_run,
                "content_type": request.META.get("CONTENT_TYPE"),
                "content_length": request.META.get("CONTENT_LENGTH"),
                "main_len_raw": len(main_raw),
                "main_len_clean": len(main_clean),
                "main_sha256_clean": _sha256_text(main_clean) if main_clean else None,
                "main_path": str(main_b64_path),
                "books_count": len(book_list or []),
                "books": books_meta,
                "received_keys": sorted(list(getattr(request.data, "keys", lambda: [])())),
            }

            (base / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

            safe_payload = {}
            try:
                for k, v in dict(request.data).items():
                    if k in ("main_xml_b64", "xml_b64", "main_b64"):
                        safe_payload[k] = f"<saved to {main_b64_path}>"
                    elif k in ("book_xml_b64_list", "books_b64", "book_b64_list"):
                        safe_payload[k] = f"<saved {len(book_list or [])} items into {base}>"
                    else:
                        safe_payload[k] = v
            except Exception:
                safe_payload = {"note": "request.data is not directly convertible to dict"}

            (base / "payload_sanitized.json").write_text(
                json.dumps(safe_payload, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )

            logger.info(f"[1C_IN] saved payload to: {base}")

        except Exception as e:
            logger.exception(f"[1C_IN] failed to log payload: {e}")


class GetReceiptPdfFromArchive1CView(APIView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        inn = str(request.data.get("inn", "")).strip()
        sbis_doc_id = str(request.data.get("sbis_doc_id", "")).strip()
        sent_date = str(request.data.get("sent_date", "")).strip()  # dd.mm.yyyy

        if not inn or not sbis_doc_id or not sent_date:
            return Response(
                {
                    "success": False,
                    "comment": "Ошибка входных данных",
                    "error": {"message": "Поля inn, sbis_doc_id, sent_date обязательны"},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        result = fetch_receipt_pdf_b64_from_archive(
            inn=inn,
            sbis_doc_id=sbis_doc_id,
            sent_date=sent_date,
        )

        if result.get("success"):
            return Response(result, status=status.HTTP_200_OK)

        return Response(result, status=status.HTTP_400_BAD_REQUEST)
