from django.urls import path

from reports.api.views.mail import MailLookupView, sbis_mail_view
from reports.api.views.nds import (
    GetReceiptPdfFromArchive1CView,
    GetSalesBookExtractView,
    SendNdsExtra1CView,
    SendNdsExtraView,
)

urlpatterns = [
    path("mail/lookup/", MailLookupView.as_view(), name="mail_lookup"),
    path("sbis/mail", sbis_mail_view, name="sbis_mail"),
    path("sbis/send-nds-extra/", SendNdsExtraView.as_view(), name="send_nds_extra"),
    path("sbis/send-nds-extra-1c/", SendNdsExtra1CView.as_view(), name="send_nds_extra_1c"),
    path("sbis/get-receipt-pdf-1c/", GetReceiptPdfFromArchive1CView.as_view(), name="get_receipt_pdf_1c"),
    path("sbis/get-sales-book-extract/", GetSalesBookExtractView.as_view(), name="get_sales_book_extract"),
]
