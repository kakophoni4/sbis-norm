import uuid
from django.db import models

class Organization(models.Model):
    inn = models.CharField(max_length=12, unique=True, verbose_name="ИНН")
    kpp = models.CharField(max_length=9, blank=True, null=True, verbose_name="КПП")
    name = models.CharField(max_length=255, verbose_name="Название")

    def __str__(self):
        return f"{self.name} (ИНН: {self.inn})"

class ReportType(models.Model):
    code = models.CharField(max_length=50, unique=True, verbose_name="Код")
    name = models.CharField(max_length=255, verbose_name="Название")
    format_version = models.CharField(max_length=20, verbose_name="Версия формата")
    period = models.JSONField(verbose_name="Период", null=True, blank=True)

    def __str__(self):
        return self.name

class Recipient(models.Model):
    code = models.CharField(max_length=50, unique=True, verbose_name="Код")
    name = models.CharField(max_length=255, blank=True, null=True, verbose_name="Название")

    def __str__(self):
        return self.name or self.code

class Document(models.Model):
    class Status(models.TextChoices):
        PENDING = 'PENDING', 'В ожидании'
        SIGNED = 'SIGNED', 'Подписан'
        UPLOADED = 'UPLOADED', 'Загружен'
        SENT = 'SENT', 'Отправлен'
        CONFIRMED = 'CONFIRMED', 'Подтвержден'
        ERROR = 'ERROR', 'Ошибка'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, verbose_name="Организация")
    report_type = models.ForeignKey(ReportType, on_delete=models.PROTECT, verbose_name="Тип отчета")
    recipient = models.ForeignKey(Recipient, on_delete=models.PROTECT, verbose_name="Получатель")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING, verbose_name="Статус")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Создан")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Обновлен")
    files = models.JSONField(verbose_name="Файлы", help_text="Массив путей к файлам")
    sbis_doc_id = models.CharField(max_length=255, blank=True, null=True, verbose_name="ID документа в СБИС")
    error_log = models.TextField(blank=True, null=True, verbose_name="Лог ошибок")
    theme = models.TextField(blank=True, null=True, verbose_name="Тема/примечание")
    svedeniya = models.JSONField(verbose_name="Служебные сведения")
    checksum = models.JSONField(verbose_name="Контрольные суммы")

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"Документ {self.id} от {self.organization.inn}"

class EventLog(models.Model):
    class EventType(models.TextChoices):
        SIGN = 'SIGN', 'Подписание'
        UPLOAD = 'UPLOAD', 'Загрузка'
        SEND = 'SEND', 'Отправка'
        STATUS_CHECK = 'STATUS_CHECK', 'Проверка статуса'

    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='events', verbose_name="Документ")
    event_type = models.CharField(max_length=20, choices=EventType.choices, verbose_name="Тип события")
    timestamp = models.DateTimeField(auto_now_add=True, verbose_name="Время")
    details = models.JSONField(blank=True, null=True, verbose_name="Детали")

    class Meta:
        ordering = ['timestamp']

    def __str__(self):
        return f"Событие {self.get_event_type_display()} для документа {self.document.id}"

class WebhookLog(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='webhooks', verbose_name="Документ")
    payload = models.JSONField(verbose_name="Тело запроса")
    response_status = models.PositiveIntegerField(verbose_name="Статус ответа")
    timestamp = models.DateTimeField(auto_now_add=True, verbose_name="Время")

    def __str__(self):
        return f"Webhook для {self.document.id} в {self.timestamp}"


class Certificate(models.Model):
    inn = models.CharField(max_length=12, db_index=True)

    # Имя контейнера как в csptest -keyset -enum_cont -fqcn: "\\.\HDIMAGE\..."
    csptest_name = models.CharField(
        max_length=255,
        unique=True,
        null=True,
        blank=True,
        verbose_name="Имя контейнера (csptest)",
        help_text="Например: \\\\.\\HDIMAGE\\c73dd937f-bcbf-6d48-f0c7-8bccbbb8297",
    )

    # Путь из uMy: "HDIMAGE\\ИНН\\XXXX" (из строки Container :)
    hdimage_path = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        verbose_name="Путь контейнера (uMy)",
        help_text="Например: HDIMAGE\\\\9715472576\\4698",
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
        choices=[('LOCAL', 'Local'), ('MEGA', 'Mega')],
        verbose_name="Источник",
    )

    # Сроки действия сертификата
    not_before = models.DateTimeField(
        blank=True,
        null=True,
        verbose_name="Действителен с",
    )
    not_after = models.DateTimeField(
        blank=True,
        null=True,
        verbose_name="Действителен по",
    )

    # Есть ли связка с приватным ключом: PrivateKey Link : Yes
    has_private_key = models.BooleanField(
        default=False,
        verbose_name="Есть приватный ключ",
    )

    installed_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(auto_now=True)

    # Когда последний раз увидели этот контейнер в csptest
    last_seen_at = models.DateTimeField(
        blank=True,
        null=True,
        verbose_name="Последний раз обнаружен",
    )

    is_active = models.BooleanField(default=True)
    meta = models.JSONField(blank=True, null=True)  # Доп. сведения (кто установил, путь до файла)

    # КПП по данным учёта/внешнего справочника (в Subject серта может не быть)
    kpp = models.CharField(
        max_length=9,
        blank=True,
        null=True,
        verbose_name="КПП",
        help_text="Для СБИС и фильтров; можно заполнить sync_org_kpp",
    )

    class Meta:
        unique_together = ('inn', 'csptest_name')

    def __str__(self):
        return f"{self.inn} [{self.csptest_name}]"


class MailCache(models.Model):
    inn = models.CharField(max_length=12, db_index=True)
    period_date = models.DateField()
    email = models.EmailField()
    attachments_meta = models.JSONField(blank=True, null=True)  # перечень вложений или ссылок
    retrieved_at = models.DateTimeField(auto_now_add=True)
    cert = models.ForeignKey(Certificate, on_delete=models.SET_NULL, null=True, blank=True)
    raw_payload = models.JSONField(blank=True, null=True)

    class Meta:
        unique_together = ('inn', 'period_date')


class CertificateAuditLog(models.Model):
    inn = models.CharField(max_length=12)
    cert = models.ForeignKey(Certificate, on_delete=models.CASCADE, null=True, blank=True)
    action = models.CharField(max_length=50)   # e.g. CHECK_LOCAL, INSTALL_FROM_MEGA, FETCH_MAIL
    status = models.CharField(max_length=20)   # SUCCESS / ERROR
    message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)


class RequirementDocument(models.Model):
    """
    Хранение требований ФНС (и подобных входящих документов): ИНН, дата, base64 PDF.
    Дедупликация: по (inn, sbis_doc_id) — один документ не дублируем;
    при повторном сканировании сверяем по (inn, document_date, content_sha256).
    """
    inn = models.CharField(max_length=12, db_index=True, verbose_name="ИНН")
    document_date = models.DateField(verbose_name="Дата документа")
    sbis_doc_id = models.CharField(
        max_length=255,
        db_index=True,
        verbose_name="Идентификатор документа в СБИС",
    )
    sbis_stage_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        verbose_name="Идентификатор этапа в СБИС",
    )
    doc_title = models.CharField(
        max_length=512,
        blank=True,
        verbose_name="Название документа",
    )
    content_sha256 = models.CharField(
        max_length=64,
        db_index=True,
        verbose_name="SHA256 содержимого (для дедупликации)",
    )
    file_b64 = models.TextField(verbose_name="Base64 содержимого PDF/XML")
    storage_file_name = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        verbose_name="Имя файла для экспорта (Требование ФНС (ИНН) (дата).pdf)",
    )
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
    """
    Отметка: для ИНН успешно выполнен опрос СписокСлужебныхЭтапов за окно дат
    в указанный календарный день (локальная дата сервера).

    Нужна, чтобы при повторном запуске той же команды в тот же день не дергать СБИС
    по организациям, где уже всё обработано (в т.ч. «0 требований» / «всё уже в БД»).

    Не создаётся, если: ошибка списка; ошибка скачивания; исключение в обработчике;
    есть документ к скачиванию, но нет этапа / нет даты документа в карточке (при фильтре по дате).
    Тогда ИНН снова участвует в следующем запуске (или в раундах повтора).
    """

    inn = models.CharField(max_length=12, db_index=True, verbose_name="ИНН")
    window_key = models.CharField(
        max_length=64,
        db_index=True,
        verbose_name="Ключ окна (date_from|date_to)",
    )
    scan_date = models.DateField(
        db_index=True,
        verbose_name="Календарный день успешного сканирования",
    )
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
