import os

from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tax_service.settings")

app = Celery("tax_service")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

from django.conf import settings

app.conf.beat_schedule = {}
default_inn = getattr(settings, "SBIS_DEFAULT_INN", "") or ""
if default_inn:
    app.conf.beat_schedule["periodic-mail-check"] = {
        "task": "reports.tasks.periodic_mail_check_task",
        "schedule": crontab(minute="*/30"),
        "args": (default_inn, 7),
    }
