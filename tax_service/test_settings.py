"""Offline unit-test settings. Never read app.env or connect to production."""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = "offline-tests-only"
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.contenttypes", "reports", "rest_framework"]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
MEDIA_ROOT = str(BASE_DIR / "media")
ROOT_URLCONF = "reports.test_sent_reports"
USE_TZ = True
REST_FRAMEWORK = {"DEFAULT_AUTHENTICATION_CLASSES": []}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
