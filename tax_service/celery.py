import os
from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tax_service.settings')

app = Celery('tax_service')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()

# Define queues
app.conf.task_queues = {
    'default': {
        'exchange': 'default',
        'binding_key': 'default',
    },
    'signing_queue': {
        'exchange': 'signing_queue',
        'binding_key': 'signing_queue',
    },
}
app.conf.task_default_queue = 'default'
app.conf.task_default_exchange = 'default'
app.conf.task_default_routing_key = 'default'
from celery.schedules import crontab

app.conf.beat_schedule = {
    'periodic-mail-check': {
        'task': 'reports.tasks.periodic_mail_check_task',
        'schedule': crontab(minute='*/30'),  # Каждые 30 минут
        'args': ('YOUR_INN_HERE', 7),  # ИНН и количество дней назад
    },
}
