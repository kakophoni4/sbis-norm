import logging
from datetime import date, timedelta

from celery import chain, shared_task
from django.utils import timezone

from .models import Certificate, CertificateAuditLog, MailCache
from .services.certificates import refresh_local_certificates
from .services.sbis_mail import SbisMailService

logger = logging.getLogger(__name__)


def upsert_mail_cache(record) -> None:
    attachments_meta = None
    if getattr(record, "attachments", None):
        attachments_meta = [
            {
                "name": att.name,
                "sbis_id": att.sbis_id,
                "category": att.category,
                "size": att.size,
            }
            for att in record.attachments
        ]

    MailCache.objects.update_or_create(
        inn=record.inn,
        period_date=record.requested_date,
        defaults={
            "email": record.email or "",
            "attachments_meta": attachments_meta,
            "retrieved_at": timezone.now(),
            "cert": Certificate.objects.filter(inn=record.inn, is_active=True).first(),
            "raw_payload": record.raw_document if record.raw_document else None,
        },
    )
    logger.info(f"Кеш обновлен для ИНН {record.inn} за дату {record.requested_date}")


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def ensure_certificate_task(self, inn: str):
    try:
        logger.info(f"[ensure_certificate_task] Проверка сертификата для ИНН {inn}")

        cert = Certificate.objects.filter(inn=inn, is_active=True).first()
        if cert:
            logger.info(f"[ensure_certificate_task] Сертификат найден: {cert.csptest_name}")
            return cert.id

        logger.info("[ensure_certificate_task] Сертификат не найден, запуск сканирования...")
        refresh_local_certificates()

        cert = Certificate.objects.filter(inn=inn, is_active=True).first()
        if cert:
            logger.info(f"[ensure_certificate_task] Сертификат найден после сканирования: {cert.csptest_name}")
            CertificateAuditLog.objects.create(
                inn=inn,
                cert=cert,
                action="ENSURE_CERT",
                status="SUCCESS",
                message=f"Сертификат найден: {cert.csptest_name}",
            )
            return cert.id

        logger.error(f"[ensure_certificate_task] Сертификат для ИНН {inn} не найден даже после сканирования")
        CertificateAuditLog.objects.create(
            inn=inn,
            cert=None,
            action="ENSURE_CERT",
            status="ERROR",
            message="Сертификат не найден.",
        )
        return None

    except Exception as exc:
        logger.exception(f"[ensure_certificate_task] Ошибка для ИНН {inn}")
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=300)
def fetch_mail_task(self, inn: str, requested_date_iso: str, include_attachments: bool = False):
    requested_date = date.fromisoformat(requested_date_iso)

    try:
        logger.info(f"[fetch_mail_task] Начало загрузки почты для ИНН {inn} за {requested_date}")

        cert = Certificate.objects.filter(inn=inn, is_active=True).first()
        if not cert:
            logger.error(f"[fetch_mail_task] Сертификат отсутствует для ИНН {inn}")
            raise ValueError(f"No certificate for INN {inn}")

        service = SbisMailService(cert)
        record = service.fetch_mail_for_date(
            requested_date,
            include_attachments=include_attachments,
            days_back=30,
        )

        if not record:
            logger.info(f"[fetch_mail_task] Письма не найдены для ИНН {inn} за {requested_date}")
            MailCache.objects.update_or_create(
                inn=inn,
                period_date=requested_date,
                defaults={
                    "email": "",
                    "attachments_meta": None,
                    "retrieved_at": timezone.now(),
                    "cert": cert,
                    "raw_payload": None,
                },
            )
            return None

        upsert_mail_cache(record)
        logger.info(f"[fetch_mail_task] Почта успешно загружена для ИНН {inn}")

        return {
            "inn": record.inn,
            "requested_date": requested_date_iso,
            "email": record.email,
            "attachments": [
                {
                    "name": att.name,
                    "sbis_id": att.sbis_id,
                    "category": att.category,
                    "size": att.size,
                }
                for att in (record.attachments or [])
            ],
            "sbis_document_id": record.sbis_document_id,
        }

    except Exception as exc:
        logger.exception(f"[fetch_mail_task] Ошибка для ИНН {inn} за {requested_date_iso}")
        raise self.retry(exc=exc)


def schedule_mail_fetch(inn: str, requested_date: date, include_attachments: bool = False):
    requested_date_iso = requested_date.isoformat()
    logger.info(f"[schedule_mail_fetch] Запуск цепочки задач для ИНН {inn}")
    workflow = chain(
        ensure_certificate_task.s(inn),
        fetch_mail_task.si(inn, requested_date_iso, include_attachments),
    )
    return workflow.apply_async()


@shared_task(bind=True)
def periodic_mail_check_task(self, inn: str, days_back: int = 7):
    try:
        logger.info(f"[periodic_mail_check_task] Периодическая проверка почты для ИНН {inn}")

        cert = Certificate.objects.filter(inn=inn, is_active=True).first()
        if not cert:
            logger.warning(f"[periodic_mail_check_task] Сертификат не найден для ИНН {inn}")
            return

        service = SbisMailService(cert)

        for days_ago in range(days_back):
            check_date = date.today() - timedelta(days=days_ago)
            cache_exists = MailCache.objects.filter(inn=inn, period_date=check_date).exists()
            if not cache_exists:
                logger.info(f"[periodic_mail_check_task] Проверка почты за {check_date}")
                record = service.fetch_mail_for_date(check_date, include_attachments=False)
                if record:
                    upsert_mail_cache(record)
                    logger.info(f"[periodic_mail_check_task] Найдена новая почта за {check_date}")

        logger.info(f"[periodic_mail_check_task] Периодическая проверка завершена для ИНН {inn}")

    except Exception as exc:
        logger.exception(f"[periodic_mail_check_task] Ошибка для ИНН {inn}")
        raise self.retry(exc=exc)
