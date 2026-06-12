from django.contrib import admin

from .models import (
    Certificate,
    CertificateAuditLog,
    MailCache,
    Organization,
    RequirementDocument,
    RequirementFetchScanState,
)


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("inn", "kpp", "name")
    search_fields = ("inn", "name")


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = ("inn", "csptest_name", "kpp", "is_active", "has_private_key", "last_seen_at")
    list_filter = ("is_active", "source", "has_private_key")
    search_fields = ("inn", "csptest_name", "thumbprint")


@admin.register(MailCache)
class MailCacheAdmin(admin.ModelAdmin):
    list_display = ("inn", "period_date", "email", "retrieved_at")
    search_fields = ("inn", "email")


@admin.register(RequirementDocument)
class RequirementDocumentAdmin(admin.ModelAdmin):
    list_display = ("inn", "document_date", "sbis_doc_id", "doc_title", "created_at")
    search_fields = ("inn", "sbis_doc_id", "doc_title")


@admin.register(RequirementFetchScanState)
class RequirementFetchScanStateAdmin(admin.ModelAdmin):
    list_display = ("inn", "window_key", "scan_date", "created_at")
    search_fields = ("inn",)


@admin.register(CertificateAuditLog)
class CertificateAuditLogAdmin(admin.ModelAdmin):
    list_display = ("inn", "action", "status", "created_at")
    list_filter = ("action", "status")
    search_fields = ("inn", "message")
