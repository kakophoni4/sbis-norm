import logging
import time
from pathlib import Path

from django.conf import settings
from reports.nodemaven_sdk.nodemaven import NodeMavenClient

CERTMGR_BIN = "/opt/cprocsp/bin/amd64/certmgr"
CRYPTCP_BIN = "/opt/cprocsp/bin/amd64/cryptcp"
CRYPTCP_DECR_FLAGS = ["-silent", "-nochain", "-norev"]
CRYPTCP_SIGN_FLAGS = ["-silent", "-nochain", "-norev"]

AUTH_URL = getattr(settings, "SBIS_AUTH_URL", "https://online.sbis.ru/auth/service/")
REPORTING_URL = getattr(settings, "SBIS_SERVICE_URL", "https://online.sbis.ru/service/?srv=1")

LOG_DIR = Path("/home/devuser/sbis_api_logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
ONEC_DECODE_DIR = LOG_DIR / "1c_decoded"
ONEC_DECODE_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger(__name__)

NODEMAVEN_COUNTRY = "RU"
NODEMAVEN_CITY = "Moscow"
NODEMAVEN_PROTOCOL = "http"

_PROXY_CACHE: dict[tuple[str, str], tuple[float, dict]] = {}
_PROXY_TTL_SECONDS = 60
_NODEMAVEN_CLIENT: NodeMavenClient | None = None
_NODEMAVEN_CLIENT_KEY: str | None = None
_GOOD_PROXY_POOL: dict[str, tuple[float, list[str]]] = {}
_GOOD_PROXY_TTL_SECONDS = 300
_PROXY_LAST_CALL_TS: dict[str, float] = {}
_PROXY_MIN_INTERVAL_SEC = 1.2
_RETRYABLE_HTTP_STATUSES = {403, 404, 429, 500, 502, 503, 504}


class CertInvalidNoRetryError(RuntimeError):
    pass
