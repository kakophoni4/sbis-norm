from datetime import datetime

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

from .sbis_api import get_session_id_by_inn, get_incoming_docs


DATE_FMT = "%d.%m.%Y"


@require_http_methods(["GET"])
def sbis_mail_view(request):
    """
    GET /api/sbis/mail?inn=9722082369&from=01.11.2025&to=03.12.2025

    1) По ИНН находит сертификат и получает SESSION_ID по подписи.
    2) Через СБИС.СписокДокументовПоСобытиям достаёт входящие за период.
    3) Возвращает JSON со списком сообщений.
    """
    inn = (request.GET.get("inn") or "").strip()
    date_from_str = request.GET.get("from")
    date_to_str = request.GET.get("to")

    if not inn or not date_from_str or not date_to_str:
        return JsonResponse(
            {"error": "inn, from, to обязательны (формат дат ДД.ММ.ГГГГ)"},
            status=400,
        )

    try:
        date_from = datetime.strptime(date_from_str, DATE_FMT)
        date_to = datetime.strptime(date_to_str, DATE_FMT)
    except ValueError:
        return JsonResponse(
            {"error": "Неверный формат даты, нужен ДД.ММ.ГГГГ"},
            status=400,
        )

    try:
        session_id = get_session_id_by_inn(inn)
        docs = get_incoming_docs(session_id, date_from, date_to)
    except Exception as e:
        return JsonResponse(
            {"error": str(e)},
            status=500,
        )

    # Приведём документы к более компактному виду
    items = []
    for doc in docs:
        kontragent = doc.get("Контрагент") or {}
        our_org = doc.get("НашаОрганизация") or {}
        attachments = doc.get("Вложение") or []

        kontr_inn = None
        if "СвЮЛ" in kontragent and "ИНН" in kontragent["СвЮЛ"]:
            kontr_inn = kontragent["СвЮЛ"]["ИНН"]
        elif "СвФЛ" in kontragent and "ИНН" in kontragent["СвФЛ"]:
            kontr_inn = kontragent["СвФЛ"]["ИНН"]

        our_inn = None
        if "СвЮЛ" in our_org and "ИНН" in our_org["СвЮЛ"]:
            our_inn = our_org["СвЮЛ"]["ИНН"]

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

    return JsonResponse(
        {
            "inn": inn,
            "from": date_from_str,
            "to": date_to_str,
            "count": len(items),
            "items": items,
        },
        safe=True,
    )
