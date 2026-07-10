from __future__ import annotations

import logging
from datetime import datetime

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from reports.models import RequirementDocument

logger = logging.getLogger(__name__)


def _check_requirements_api_token(request) -> Response | None:
    """Если REQUIREMENTS_API_TOKEN задан — требуем заголовок X-API-Key или Bearer."""
    expected = (getattr(settings, "REQUIREMENTS_API_TOKEN", None) or "").strip()
    if not expected:
        return None
    got = (request.headers.get("X-API-Key") or "").strip()
    if not got:
        auth = (request.headers.get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            got = auth[7:].strip()
    if got != expected:
        return Response({"detail": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
    return None


def _serialize_requirement(doc: RequirementDocument, *, include_file: bool = False) -> dict:
    data = {
        "id": doc.id,
        "inn": doc.inn,
        "document_date": doc.document_date.isoformat() if doc.document_date else None,
        "sbis_doc_id": doc.sbis_doc_id,
        "sbis_stage_id": doc.sbis_stage_id,
        "doc_title": doc.doc_title,
        "content_sha256": doc.content_sha256,
        "storage_file_name": doc.storage_file_name,
        "created_at": doc.created_at.isoformat() if doc.created_at else None,
        "external_synced_at": doc.external_synced_at.isoformat() if doc.external_synced_at else None,
        "file_size": len(doc.file_b64 or "") * 3 // 4 if doc.file_b64 else 0,
    }
    if include_file:
        data["file_b64"] = doc.file_b64 or ""
    return data


class RequirementsListView(APIView):
    """
    Список требований ФНС из БД (для внешнего сервиса).

    GET /api/sbis/requirements/
      ?inn=9707039440
      &date_from=2026-06-01
      &date_to=2026-07-10
      &since_id=0
      &unsynced=1
      &include_file=0
      &limit=50
    """

    permission_classes = []

    def get(self, request, *args, **kwargs):
        denied = _check_requirements_api_token(request)
        if denied:
            return denied

        qs = RequirementDocument.objects.all().order_by("id")
        inn = str(request.query_params.get("inn") or "").strip()
        if inn:
            qs = qs.filter(inn=inn)

        date_from = parse_date(str(request.query_params.get("date_from") or "").strip() or "")
        date_to = parse_date(str(request.query_params.get("date_to") or "").strip() or "")
        if date_from:
            qs = qs.filter(document_date__gte=date_from)
        if date_to:
            qs = qs.filter(document_date__lte=date_to)

        since_id = request.query_params.get("since_id")
        if since_id not in (None, ""):
            try:
                qs = qs.filter(id__gt=int(since_id))
            except (TypeError, ValueError):
                return Response({"detail": "since_id must be int"}, status=status.HTTP_400_BAD_REQUEST)

        since_created = str(request.query_params.get("since_created_at") or "").strip()
        if since_created:
            dt = parse_datetime(since_created) or parse_date(since_created)
            if isinstance(dt, datetime):
                qs = qs.filter(created_at__gte=dt)
            elif dt:
                qs = qs.filter(created_at__date__gte=dt)

        unsynced = str(request.query_params.get("unsynced") or "").strip().lower() in ("1", "true", "yes")
        if unsynced:
            qs = qs.filter(external_synced_at__isnull=True)

        try:
            limit = max(1, min(500, int(request.query_params.get("limit") or 50)))
        except (TypeError, ValueError):
            limit = 50

        include_file = str(request.query_params.get("include_file") or "").strip().lower() in ("1", "true", "yes")
        rows = list(qs[:limit])
        return Response(
            {
                "count": len(rows),
                "results": [_serialize_requirement(r, include_file=include_file) for r in rows],
            }
        )


class RequirementDetailView(APIView):
    """GET /api/sbis/requirements/<id>/ — мета + file_b64."""

    permission_classes = []

    def get(self, request, pk: int, *args, **kwargs):
        denied = _check_requirements_api_token(request)
        if denied:
            return denied
        doc = RequirementDocument.objects.filter(pk=pk).first()
        if not doc:
            return Response({"detail": "not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(_serialize_requirement(doc, include_file=True))


class RequirementsMarkSyncedView(APIView):
    """
    POST /api/sbis/requirements/mark-synced/
    body: {"ids": [1,2,3]}  — пометить как забранные внешним сервисом
    """

    permission_classes = []

    def post(self, request, *args, **kwargs):
        denied = _check_requirements_api_token(request)
        if denied:
            return denied
        ids = request.data.get("ids") or request.data.get("id_list") or []
        if not isinstance(ids, list) or not ids:
            return Response({"detail": "ids[] required"}, status=status.HTTP_400_BAD_REQUEST)
        clean_ids = []
        for x in ids:
            try:
                clean_ids.append(int(x))
            except (TypeError, ValueError):
                continue
        if not clean_ids:
            return Response({"detail": "no valid ids"}, status=status.HTTP_400_BAD_REQUEST)
        now = timezone.now()
        updated = RequirementDocument.objects.filter(id__in=clean_ids).update(external_synced_at=now)
        return Response({"updated": updated, "synced_at": now.isoformat()})
