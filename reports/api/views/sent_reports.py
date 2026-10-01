import logging

from rest_framework.response import Response
from rest_framework.views import APIView

from reports.api.permissions import OneCApiTokenPermission
from reports.services.sbis.sent_reports import ReportError, list_sent_reports, download_sent_report

logger = logging.getLogger(__name__)


class SentReportsBaseView(APIView):
    permission_classes = [OneCApiTokenPermission]

    def post(self, request):
        if not isinstance(request.data, dict):
            return Response({"success": False, "error": {"code": "invalid_input",
                             "message": "Ожидается JSON-объект"}}, status=400)
        try:
            result = self.run(request.data)
            # 200 with explicit complete=false is a partial scan, never an empty success.
            return Response(result)
        except ReportError as exc:
            return Response({"success": False, "error": {
                "code": exc.code, "message": exc.message}}, status=exc.status)
        except Exception as exc:
            logger.error("[1C_SENT_REPORTS] internal error type=%s", type(exc).__name__)
            return Response({"success": False, "error": {"code": "internal_error",
                             "message": "Внутренняя ошибка сервиса"}}, status=500)


class SentReports1CView(SentReportsBaseView):
    def run(self, data):
        return list_sent_reports(data.get("inn"), data.get("days"))


class SentReportXml1CView(SentReportsBaseView):
    def run(self, data):
        return download_sent_report(data.get("inn"), data.get("sbis_doc_id"), data.get("sent_date"))
