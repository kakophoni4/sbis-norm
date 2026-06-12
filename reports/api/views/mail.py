import logging
from datetime import datetime, timedelta

from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from pydantic import ValidationError
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from reports.api.schemas import MailLookupRequest, MailLookupResponse
from reports.models import Certificate, MailCache
from reports.services.sbis_mail import SbisMailService
from reports.tasks import schedule_mail_fetch

logger = logging.getLogger(__name__)

DATE_FMT = "%d.%m.%Y"


class MailLookupView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            payload = MailLookupRequest(**request.data)
        except ValidationError as exc:
            return Response(exc.errors(), status=status.HTTP_400_BAD_REQUEST)

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
                message="Сертификат для данного ИНН не найден.",
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
                message="Задача запущена.",
                email=None,
                attachments=None,
            )
            return Response(resp.dict(), status=status.HTTP_202_ACCEPTED)
        except Exception as e:
            logger.exception(f"Ошибка запуска задачи почты: {e}")
            resp = MailLookupResponse(
                inn=payload.inn,
                requested_date=payload.requested_date,
                status="ERROR",
                message=str(e),
                email=None,
                attachments=None,
            )
            return Response(resp.dict(), status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@require_http_methods(["GET"])
def sbis_mail_view(request):
    inn = (request.GET.get("inn") or "").strip()
    date_from_str = request.GET.get("from")
    date_to_str = request.GET.get("to")

    if not inn or not date_from_str or not date_to_str:
        return JsonResponse(
            {"error": "inn, from, to обязательны (формат дат ДД.ММ.ГГГГ)"},
            status=400,
        )

    try:
        date_from = datetime.strptime(date_from_str, DATE_FMT).date()
        date_to = datetime.strptime(date_to_str, DATE_FMT).date()
    except ValueError:
        return JsonResponse({"error": "Неверный формат даты"}, status=400)

    cert = Certificate.objects.filter(inn=inn, is_active=True).first()
    if not cert:
        return JsonResponse({"error": f"Сертификат не найден для ИНН {inn}"}, status=404)

    try:
        service = SbisMailService(cert)
        items = []
        current = date_from
        while current <= date_to:
            record = service.fetch_mail_for_date(current, include_attachments=True, days_back=0)
            if record and record.raw_document:
                doc = record.raw_document
                kontragent = doc.get("Контрагент") or {}
                our_org = doc.get("НашаОрганизация") or {}
                attachments = doc.get("Вложение") or []
                kontr_inn = None
                if "СвЮЛ" in kontragent:
                    kontr_inn = (kontragent["СвЮЛ"] or {}).get("ИНН")
                elif "СвФЛ" in kontragent:
                    kontr_inn = (kontragent["СвФЛ"] or {}).get("ИНН")
                our_inn = (our_org.get("СвЮЛ") or {}).get("ИНН") if "СвЮЛ" in our_org else None
                items.append(
                    {
                        "date": doc.get("Дата"),
                        "title": doc.get("Название"),
                        "direction": doc.get("Направление"),
                        "counterparty_inn": kontr_inn,
                        "our_inn": our_inn,
                        "our_name": (our_org.get("СвЮЛ") or {}).get("Название"),
                        "attachments": [
                            {
                                "name": att.get("Название"),
                                "id": att.get("Идентификатор"),
                                "href_pdf": att.get("СсылкаНаPDF"),
                                "href_file": (att.get("Файл") or {}).get("Ссылка"),
                            }
                            for att in attachments
                        ],
                    }
                )
            current += timedelta(days=1)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse(
        {"inn": inn, "from": date_from_str, "to": date_to_str, "count": len(items), "items": items},
        safe=True,
    )
