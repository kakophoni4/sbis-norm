from django.urls import path

from .views import (
    SubmitReportView,
    ReportStatusView,
    WebhookTestView,
    MailLookupView,
    SendNdsExtraView,
    SendNdsExtra1CView,
    GetReceiptPdfFromArchive1CView,
)
from .views_mail import sbis_mail_view

urlpatterns = [
    path("reports/submit/", SubmitReportView.as_view(), name="submit_report"),
    path("reports/<uuid:id>/status/", ReportStatusView.as_view(), name="report_status"),
    path("webhook/test/", WebhookTestView.as_view(), name="webhook_test"),
    path("mail/lookup/", MailLookupView.as_view(), name="mail_lookup"),
    path("sbis/mail", sbis_mail_view, name="sbis_mail"),
    path("sbis/send-nds-extra/", SendNdsExtraView.as_view(), name="send_nds_extra"),
    path("sbis/send-nds-extra-1c/", SendNdsExtra1CView.as_view(), name="send_nds_extra_1c"),
    path("sbis/get-receipt-pdf-1c/", GetReceiptPdfFromArchive1CView.as_view(), name="get_receipt_pdf_1c"),
]
