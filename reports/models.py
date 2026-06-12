from django.db import models


class Organization(models.Model):
    inn = models.CharField(max_length=12, unique=True, verbose_name="ИНН")
    kpp = models.CharField(max_length=9, blank=True, null=True, verbose_name="КПП")
    name = models.CharField(max_length=255, verbose_name="Название")

    def __str__(self):
        return f"{self.name} (ИНН: {self.inn})"


class Certificate(models.Model):
    inn = models.CharField(max_length=12, db_index=True)
    csptest_name = models.CharField(
        max_length=255,
        unique=True,
        null=True,
        blank=True,
        verbose_name="Имя контейнера (csptest)",
    )
    hdimage_path = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        verbose_name="Путь контейнера (uMy)",
    )
    thumbprint = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        db_index=True,
        verbose_name="SHA1 отпечаток",
    )
    source = models.CharField(
        max_length=20,
        choices=[("LOCAL", "Local"), ("MEGA", "Mega")],
        verbose_name="Источник",
    )
    not_before = models.DateTimeField(blank=True, null=True, verbose_name="Действителен с")
    not_after = models.DateTimeField(blank=True, null=True, verbose_name="Действителен по")
    has_private_key = models.BooleanField(default=False, verbose_name="Есть приватный ключ")
    installed_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(auto_now=True)
    last_seen_at = models.DateTimeField(blank=True, null=True, verbose_name="Последний раз обнаружен")
    is_active = models.BooleanField(default=True)
    meta = models.JSONField(blank=True, null=True)
    kpp = models.CharField(max_length=9, blank=True, null=True, verbose_name="КПП")

    class Meta:
        unique_together = ("inn", "csptest_name")

    def __str__(self):
        return f"{self.inn} [{self.csptest_name}]"


class MailCache(models.Model):
    inn = models.CharField(max_length=12, db_index=True)
    period_date = models.DateField()
    email = models.EmailField()
    attachments_meta = models.JSONField(blank=True, null=True)
    retrieved_at = models.DateTimeField(auto_now_add=True)
    cert = models.ForeignKey(Certificate, on_delete=models.SET_NULL, null=True, blank=True)
    raw_payload = models.JSONField(blank=True, null=True)

    class Meta:
        unique_together = ("inn", "period_date")


class CertificateAuditLog(models.Model):
    inn = models.CharField(max_length=12)
    cert = models.ForeignKey(Certificate, on_delete=models.CASCADE, null=True, blank=True)
    action = models.CharField(max_length=50)
    status = models.CharField(max_length=20)
    message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)


class RequirementDocument(models.Model):
    inn = models.CharField(max_length=12, db_index=True, verbose_name="ИНН")
    document_date = models.DateField(verbose_name="Дата документа")
    sbis_doc_id = models.CharField(max_length=255, db_index=True, verbose_name="Идентификатор документа в СБИС")
    sbis_stage_id = models.CharField(max_length=255, blank=True, null=True, verbose_name="Идентификатор этапа в СБИС")
    doc_title = models.CharField(max_length=512, blank=True, verbose_name="Название документа")
    content_sha256 = models.CharField(max_length=64, db_index=True, verbose_name="SHA256 содержимого")
    file_b64 = models.TextField(verbose_name="Base64 содержимого PDF/XML")
    storage_file_name = models.CharField(max_length=255, blank=True, null=True, verbose_name="Имя файла для экспорта")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Создано")

    class Meta:
        verbose_name = "Требование (документ ФНС)"
        verbose_name_plural = "Требования (документы ФНС)"
        unique_together = (("inn", "sbis_doc_id"),)
        ordering = ["-document_date", "-created_at"]
        indexes = [
            models.Index(fields=["inn", "document_date", "content_sha256"]),
        ]

    def __str__(self):
        return f"{self.inn} {self.document_date} {self.sbis_doc_id}"


class RequirementFetchScanState(models.Model):
    inn = models.CharField(max_length=12, db_index=True, verbose_name="ИНН")
    window_key = models.CharField(max_length=64, db_index=True, verbose_name="Ключ окна")
    scan_date = models.DateField(db_index=True, verbose_name="Календарный день успешного сканирования")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Создано")

    class Meta:
        verbose_name = "Отметка сканирования требований"
        verbose_name_plural = "Отметки сканирования требований"
        constraints = [
            models.UniqueConstraint(
                fields=["inn", "window_key", "scan_date"],
                name="uniq_req_fetch_scan_inn_window_day",
            ),
        ]

    def __str__(self):
        return f"{self.inn} {self.window_key} @ {self.scan_date}"
