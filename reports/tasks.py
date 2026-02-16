# reports/tasks.py

import json
import logging
from datetime import date, timedelta
from typing import Optional

from celery import chain, shared_task
from django.utils import timezone

from .models import Certificate, Document, EventLog, MailCache, CertificateAuditLog
from .services.certificates import ensure_certificate_record, refresh_local_certificates
from .services.sbis import SbisMailService

logger = logging.getLogger(__name__)


def upsert_mail_cache(record) -> None:
    """Обновляет или создаёт запись в MailCache на основе ответа СБИС."""
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
def ensure_certificate_task(self, inn: str) -> Optional[int]:
    """
    Гарантирует наличие активного сертификата для заданного ИНН.
    
    Логика:
    1. Проверяет наличие сертификата в БД
    2. Если нет - запускает сканирование локальных контейнеров
    3. Если всё ещё нет - логирует ошибку (в будущем - установка с MEGA)
    """
    try:
        logger.info(f"[ensure_certificate_task] Проверка сертификата для ИНН {inn}")
        
        # Проверяем наличие в БД
        cert = Certificate.objects.filter(inn=inn, is_active=True).first()
        
        if cert:
            logger.info(f"[ensure_certificate_task] Сертификат найден: {cert.container_path}")
            return cert.id
        
        # Сканируем локальные контейнеры
        logger.info(f"[ensure_certificate_task] Сертификат не найден, запуск сканирования...")
        refresh_local_certificates()
        
        # Проверяем снова
        cert = Certificate.objects.filter(inn=inn, is_active=True).first()
        
        if cert:
            logger.info(f"[ensure_certificate_task] Сертификат найден после сканирования: {cert.container_path}")
            CertificateAuditLog.objects.create(
                inn=inn,
                cert=cert,
                action="ENSURE_CERT",
                status="SUCCESS",
                message=f"Сертификат найден: {cert.container_path}"
            )
            return cert.id
        
        # TODO: Здесь должна быть логика установки с MEGA
        logger.error(f"[ensure_certificate_task] Сертификат для ИНН {inn} не найден даже после сканирования")
        CertificateAuditLog.objects.create(
            inn=inn,
            cert=None,
            action="ENSURE_CERT",
            status="ERROR",
            message="Сертификат не найден. Требуется установка с MEGA (не реализовано)."
        )
        return None
        
    except Exception as exc:
        logger.exception(f"[ensure_certificate_task] Ошибка для ИНН {inn}")
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=300)
def fetch_mail_task(
    self, inn: str, requested_date_iso: str, include_attachments: bool = False
) -> Optional[dict]:
    """
    Загружает письма из СБИС за указанную дату и кэширует результат.
    """
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
            days_back=30  # Ищем в пределах 30 дней
        )

        if not record:
            logger.info(f"[fetch_mail_task] Письма не найдены для ИНН {inn} за {requested_date}")
            # Создаем пустую запись в кеше, чтобы не запрашивать повторно
            MailCache.objects.update_or_create(
                inn=inn,
                period_date=requested_date,
                defaults={
                    "email": "",
                    "attachments_meta": None,
                    "retrieved_at": timezone.now(),
                    "cert": cert,
                    "raw_payload": None,
                }
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


def schedule_mail_fetch(
    inn: str, requested_date: date, include_attachments: bool = False
):
    """
    Формирует цепочку ensure_certificate_task -> fetch_mail_task и отправляет её в Celery.
    """
    requested_date_iso = requested_date.isoformat()
    
    logger.info(f"[schedule_mail_fetch] Запуск цепочки задач для ИНН {inn}")
    
    ensure_signature = ensure_certificate_task.s(inn)
    fetch_signature = fetch_mail_task.si(inn, requested_date_iso, include_attachments)
    
    workflow = chain(ensure_signature, fetch_signature)
    return workflow.apply_async()


@shared_task(bind=True)
def periodic_mail_check_task(self, inn: str, days_back: int = 7):
    """
    Периодическая задача для проверки новой почты.
    Можно запускать через Celery Beat.
    """
    try:
        logger.info(f"[periodic_mail_check_task] Периодическая проверка почты для ИНН {inn}")
        
        cert = Certificate.objects.filter(inn=inn, is_active=True).first()
        if not cert:
            logger.warning(f"[periodic_mail_check_task] Сертификат не найден для ИНН {inn}")
            return
        
        service = SbisMailService(cert)
        
        # Проверяем почту за последние N дней
        for days_ago in range(days_back):
            check_date = date.today() - timedelta(days=days_ago)
            
            # Проверяем, есть ли уже в кеше
            cache_exists = MailCache.objects.filter(
                inn=inn,
                period_date=check_date
            ).exists()
            
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


# Задачи для обработки отчетов (оставляем без изменений)

@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def sign_report(self, document_id):
    """ЗАДАЧА-ЗАГЛУШКА: Подписание отчета."""
    try:
        doc = Document.objects.get(id=document_id)
        logger.info(f"[sign_report] Начало имитации подписания для документа {document_id}")

        doc.status = Document.Status.SIGNED
        doc.save(update_fields=["status", "updated_at"])

        EventLog.objects.create(
            document=doc,
            event_type=EventLog.EventType.SIGN,
            details={"message": "Документ успешно подписан (ИМИТАЦИЯ)."},
        )
        logger.info(f"[sign_report] Документ {document_id} помечен как подписанный.")
        return document_id
    except Document.DoesNotExist:
        logger.error(f"[sign_report] Документ с ID {document_id} не найден.")
    except Exception as e:
        logger.error(f"[sign_report] Ошибка при имитации подписания: {e}")
        self.retry(exc=e)


@shared_task(bind=True, max_retries=3, default_retry_delay=300)
def upload_and_send(self, document_id):
    """Задача для загрузки и отправки отчета в СБИС."""
    try:
        doc = Document.objects.get(id=document_id)
        logger.info(f"[upload_and_send] Начало загрузки документа {document_id} в СБИС.")

        sbis_doc_id = f"sbis-imitation-id-{doc.id}"

        doc.sbis_doc_id = sbis_doc_id
        doc.status = Document.Status.SENT
        doc.save(update_fields=["status", "sbis_doc_id", "updated_at"])

        EventLog.objects.create(
            document=doc,
            event_type=EventLog.EventType.UPLOAD,
            details={
                "message": "Документ отправлен в СБИС (ИМИТАЦИЯ).",
                "sbis_doc_id": sbis_doc_id,
            },
        )
        logger.info(f"[upload_and_send] Документ {document_id} отправлен. SBIS ID: {sbis_doc_id}")
        return document_id

    except Document.DoesNotExist:
        logger.error(f"[upload_and_send] Документ с ID {document_id} не найден.")
    except Exception as e:
        logger.error(f"[upload_and_send] Ошибка при имитации отправки: {e}")
        if "doc" in locals():
            doc.status = Document.Status.ERROR
            doc.error_log = str(e)
            doc.save(update_fields=["status", "error_log", "updated_at"])
        raise self.retry(exc=e)


@shared_task(bind=True)
def monitor_status(self, document_id):
    """Задача для мониторинга статуса отчета в СБИС."""
    try:
        doc = Document.objects.get(id=document_id)
        if not doc.sbis_doc_id:
            logger.warning(f"[monitor_status] У документа {document_id} нет SBIS ID")
            return

        logger.info(f"[monitor_status] Проверка статуса для SBIS ID: {doc.sbis_doc_id}")

        doc.status = Document.Status.CONFIRMED
        doc.save(update_fields=["status", "updated_at"])
        
        EventLog.objects.create(
            document=doc,
            event_type=EventLog.EventType.STATUS_CHECK,
            details={"message": "Статус документа подтвержден ФНС (ИМИТАЦИЯ)."},
        )
        logger.info(f"[monitor_status] Документ {document_id} получил финальный статус.")

    except Document.DoesNotExist:
        logger.error(f"[monitor_status] Документ с ID {document_id} не найден.")
    except Exception as e:
        logger.error(f"[monitor_status] Ошибка при имитации мониторинга: {e}")


def start_report_processing_chain(document_id):
    """Запускает цепочку задач Celery для обработки отчета."""
    processing_chain = chain(
        sign_report.s(document_id),
        upload_and_send.s(),
        monitor_status.s(),
    )
    processing_chain.apply_async()
    logger.info(f"Запущена единая цепочка обработки для документа {document_id}")
