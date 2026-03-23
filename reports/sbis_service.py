import base64
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import random
import threading
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path
import io
import zipfile
import requests
import time
from requests.exceptions import ProxyError, SSLError, ConnectionError, Timeout
from urllib.parse import urlparse, urlunparse
from django.conf import settings
from reports.nodemaven_sdk.nodemaven import NodeMavenClient
from reports.models import Certificate
from requests.adapters import HTTPAdapter


CERTMGR_BIN = "/opt/cprocsp/bin/amd64/certmgr"
CRYPTCP_BIN = "/opt/cprocsp/bin/amd64/cryptcp"
# Без этих флагов cryptcp спрашивает "Do you want to use this certificate?" при непроверенной цепочке/отзыве
CRYPTCP_DECR_FLAGS = ["-silent", "-nochain", "-norev"]
CRYPTCP_SIGN_FLAGS = ["-silent", "-nochain", "-norev"]


def _csp_use_sudo() -> bool:
    """Если True, certmgr/cryptcp запускаются через sudo (ключи в /var/opt/cprocsp/keys/root)."""
    return getattr(settings, "CSP_USE_SUDO", True)

AUTH_URL = "https://online.sbis.ru/auth/service/"
REPORTING_URL = "https://online.sbis.ru/service/?srv=1"

LOG_DIR = Path("/home/devuser/sbis_api_logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

ONEC_DECODE_DIR = LOG_DIR / "1c_decoded"
ONEC_DECODE_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger(__name__)

NODEMAVEN_COUNTRY = "RU"
NODEMAVEN_CITY = "Moscow"
NODEMAVEN_PROTOCOL = "http"
NODEMAVEN_APIKEY_HARDCODE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzYzOTI2MjgwLCJpYXQiOjE3NjM5MjQ0ODAsImp0aSI6IjYyZDAyOTE4NTlkMTRlODVhNTg3ZTY5MjJhY2FlOWZkIiwidXNlcl9pZCI6Ijc0MThlNjdjLThlZDYtNGJjNC04Y2RhLTgxOTYzZWRjMDVlZiJ9.OZ-GgdKV_dwbn-IA-iKTk_FcDeDgdoDhx4otY_3GrII"
_PROXY_CACHE: dict[tuple[str, str], tuple[float, dict]] = {}
_PROXY_TTL_SECONDS = 60

_NODEMAVEN_CLIENT: NodeMavenClient | None = None
_NODEMAVEN_CLIENT_KEY: str | None = None

_GOOD_PROXY_POOL: dict[str, tuple[float, list[str]]] = {}  # inn -> (ts, [proxy_url...])
_GOOD_PROXY_TTL_SECONDS = 300  # 5 минут

_PROXY_LAST_CALL_TS: dict[str, float] = {}  # inn -> timestamp

_PROXY_MIN_INTERVAL_SEC = 1.2  # минимум между запросами через прокси на один ИНН

_RETRYABLE_HTTP_STATUSES = {403, 404, 429, 500, 502, 503, 504}  # 403 — лимит/доступ, пробуем другой прокси; 404 — сбой туннеля


class CertInvalidNoRetryError(RuntimeError):
    """Сертификат отозван/просрочен/не доверенный — не перебирать прокси, сразу выйти."""
    pass


def _is_retryable_http_status(code: int) -> bool:
    try:
        return int(code) in _RETRYABLE_HTTP_STATUSES
    except Exception:
        return False


def _short_body(resp: requests.Response, limit: int = 200) -> str:
    try:
        t = resp.text or ""
        t = t.replace("\n", " ").replace("\r", " ")
        return t[:limit]
    except Exception:
        return ""


def _request_body_preview_for_log(data, max_len: int = 1200) -> str:
    """Тело запроса для лога: без длинного base64, чтобы видеть ИНН/ФИО."""
    if data is None:
        return "(no body)"
    try:
        raw = data.decode("utf-8") if isinstance(data, bytes) else data
    except Exception:
        return "(body decode error)"
    if not raw or not raw.strip():
        return "(empty)"
    try:
        obj = json.loads(raw)
        # Подменить ДвоичныеДанные в params.Сертификат
        params = obj.get("params") if isinstance(obj, dict) else None
        if isinstance(params, dict) and "Сертификат" in params:
            cert = params["Сертификат"]
            if isinstance(cert, dict) and "ДвоичныеДанные" in cert:
                b64 = cert["ДвоичныеДанные"]
                n = len(b64) if isinstance(b64, str) else 0
                cert = {**cert, "ДвоичныеДанные": f"<base64 {n} chars>"}
                params = {**params, "Сертификат": cert}
                obj = {**obj, "params": params}
        out = json.dumps(obj, ensure_ascii=False)
        return out[:max_len] + ("..." if len(out) > max_len else "")
    except Exception:
        return (raw[:max_len] + ("..." if len(raw) > max_len else "")) + " (raw)"


def _close_http_response(resp: requests.Response | None) -> None:
    """Освободить сокет/соединение urllib3 (важно при ретраях и stream=True)."""
    if resp is None:
        return
    try:
        resp.close()
    except Exception:
        pass


def _is_revoked_or_untrusted_cert_response(body_text: str) -> bool:
    """
    Тело ответа СБИС: сертификат отозван / не доверенный / просрочен — не ретраим.
    Также: регистрация клиента не завершилась — не ретраим (не проблема прокси).
    """
    if not body_text:
        return False
    t = body_text.lower()
    return (
        "отозван" in t
        or "не является доверенным" in t
        or "выберите другой сертификат" in t
        or "просроченному сертификату" in t
        or "аутентификация по просроченному" in t
        or "регистрация клиента еще не завершилась" in t
        or "регистрация клиента ещё не завершилась" in t
        or "схема для клиента в процессе разворачи" in t
    )


def _nodemaven_client() -> NodeMavenClient:
    global _NODEMAVEN_CLIENT, _NODEMAVEN_CLIENT_KEY

    api_key = (os.getenv("NODEMAVEN_APIKEY") or "").strip()
    if not api_key:
        api_key = (NODEMAVEN_APIKEY_HARDCODE or "").strip()

    if not api_key:
        raise RuntimeError("NODEMAVEN_APIKEY не задан (ни env, ни хардкод)")

    if _NODEMAVEN_CLIENT is None or _NODEMAVEN_CLIENT_KEY != api_key:
        _NODEMAVEN_CLIENT = NodeMavenClient(api_key=api_key)
        _NODEMAVEN_CLIENT_KEY = api_key

    return _NODEMAVEN_CLIENT

def _replace_port_in_proxy_url(proxy_url: str, new_port: int) -> str:
    u = urlparse(proxy_url)
    netloc = u.netloc
    userinfo = ""
    hostport = netloc
    if "@" in netloc:
        userinfo, hostport = netloc.split("@", 1)

    host = hostport.split(":", 1)[0]
    new_netloc = f"{userinfo+'@' if userinfo else ''}{host}:{int(new_port)}"
    return urlunparse((u.scheme, new_netloc, u.path, u.params, u.query, u.fragment))

_thread_http = threading.local()


def _thread_local_sbis_session() -> requests.Session:
    """
    Отдельный requests.Session на поток (ThreadPoolExecutor), без общего кэша:
    один глобальный Session + много потоков → гонки и рост открытых сокетов (EMFILE).

    Маленький пул соединений: при N воркерах не раздуваем FD как pool×N×хостов.
    """
    s = getattr(_thread_http, "sess", None)
    if s is not None:
        return s
    sess = requests.Session()
    adapter = HTTPAdapter(max_retries=0, pool_connections=2, pool_maxsize=4)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    _thread_http.sess = sess
    return sess


def _nodemaven_proxies(inn: str, sticky_key: str, *, city: str | None = NODEMAVEN_CITY) -> dict:
    """
    Возвращает proxies для requests.
    city можно убрать (None), это часто стабильнее, если Moscow даёт 500/429.
    """
    cache_key = (inn or "no_inn", sticky_key or "sbis", city or "")
    now = time.time()

    cached = _PROXY_CACHE.get(cache_key)
    if cached and (now - cached[0]) < _PROXY_TTL_SECONDS:
        return cached[1]

    client = _nodemaven_client()

    payload = {
        "country": NODEMAVEN_COUNTRY,
        "session": f"sbis_{inn}_{sticky_key}",
    }
    if city:
        payload["city"] = city

    cfg = client.getProxyConfig(payload)

    if not (isinstance(cfg, dict) and ("http" in cfg or "https" in cfg)):
        raise RuntimeError(f"NodeMaven вернул неожиданный proxy config: {cfg!r}")

    p = (cfg.get("http") or cfg.get("https") or "").strip()
    if not p:
        raise RuntimeError(f"NodeMaven вернул пустой proxy url: {cfg!r}")

    # для HTTPS назначения proxy URL должен быть http://... (CONNECT)
    proxies = {"http": p, "https": p}

    _PROXY_CACHE[cache_key] = (now, proxies)
    return proxies

def _mask_proxy_url(proxy_url: str) -> str:
    # Чтобы случайно не спалить логин/пароль в принтах
    try:
        u = urlparse(proxy_url)
        netloc = u.netloc
        if "@" in netloc:
            creds, hostport = netloc.split("@", 1)
            if ":" in creds:
                user = creds.split(":", 1)[0]
                netloc = f"{user}:***@{hostport}"
            else:
                netloc = f"***@{hostport}"
        return urlunparse((u.scheme, netloc, u.path, u.params, u.query, u.fragment))
    except Exception:
        return "<proxy>"


def _probe_proxy_connectivity(
    proxy_url: str,
    *,
    test_url: str = "https://online.sbis.ru/service/?srv=1",
    timeout: float = 6.0,
) -> tuple[bool, str]:
    """
    Очень мягкая проверка: важен факт CONNECT и хоть какой-то ответ.
    Если ловим 429/5xx — это почти всегда прокси-лимит/туннель, считаем 'плохой сейчас'.
    """
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        # stream=True: без close/with соединения копятся → Too many open files
        with requests.get(
            test_url,
            timeout=timeout,
            proxies=proxies,
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "sbis-proxy-probe/1.0"},
        ) as r:
            code = int(r.status_code)

            if code in (429, 500, 502, 503, 504):
                return False, f"bad_status={code}"

            return True, f"ok_status={code}"

    except requests.exceptions.ProxyError as e:
        return False, f"proxy_error={e}"
    except (SSLError, ConnectionError, Timeout) as e:
        return False, f"net_error={e}"
    except Exception as e:
        return False, f"error={e}"


def warmup_good_proxies_for_inn(
    inn: str,
    *,
    want: int = 2,
    total_budget_sec: int = 18,
    per_probe_timeout: float = 6.0,
) -> list[str]:
    """
    Мягкий прогрев:
    - ищем 1–2 рабочих прокси
    - не делаем много проб подряд, иначе сами ловим 429
    """
    logger.info(
        "[SBIS_PROXY_POOL] warmup start inn=%s want=%s budget_sec=%s",
        inn, want, total_budget_sec,
    )
    deadline = time.time() + max(8, int(total_budget_sec))
    good: list[str] = []

    ports = [8080, 8081, 8082, 8083, 8085, 8090, 8100]
    random.shuffle(ports)

    city_modes = [None, NODEMAVEN_CITY]  # чаще без city стабильнее

    tries = 0
    while time.time() < deadline and len(good) < want:
        tries += 1
        sticky = uuid.uuid4().hex[:8]

        for city in city_modes:
            if time.time() >= deadline or len(good) >= want:
                break

            try:
                p = _nodemaven_proxies(inn=inn, sticky_key=sticky, city=city)
                base = (p.get("http") or "").strip()
                if not base:
                    continue
            except Exception:
                continue

            for port in ports:
                if time.time() >= deadline or len(good) >= want:
                    break

                proxy_url = _replace_port_in_proxy_url(base, port)
                if proxy_url in good:
                    continue

                ok, reason = _probe_proxy_connectivity(proxy_url, timeout=per_probe_timeout)
                if ok:
                    good.append(proxy_url)
                else:
                    # если видим 429 — тормозим, иначе быстро упрёмся в лимит
                    if "bad_status=429" in reason:
                        time.sleep(4.0)

                # лёгкая пауза между пробами
                time.sleep(0.7)

    if good:
        _GOOD_PROXY_POOL[inn] = (time.time(), good)

    logger.info(
        f"[SBIS_PROXY_POOL] warmup inn={inn} collected={len(good)} tries={tries} "
        f"sample={[ _mask_proxy_url(x) for x in good[:2] ]}"
    )
    return good



def get_good_proxy_for_inn(inn: str) -> str | None:
    """
    Берем рабочий proxy_url из пула (если не протух).
    """
    cached = _GOOD_PROXY_POOL.get(inn)
    if not cached:
        return None
    ts, arr = cached
    if (time.time() - ts) > _GOOD_PROXY_TTL_SECONDS or not arr:
        _GOOD_PROXY_POOL.pop(inn, None)
        return None
    return random.choice(arr)

def _sbis_request(
    method: str,
    url: str,
    *,
    headers: dict,
    data=None,
    timeout: int = 30,
    inn: str | None = None,
    allow_redirects: bool = True,
    proxy_url_override: str | None = None,
    total_budget_sec: int = 45,
):
    """
    Главная точка HTTP.
    Ретраим:
      - ProxyError/Timeout/ConnectionError/SSLError
      - "плохие" HTTP статусы: 429/500/502/503/504
    При ретраях крутим порты + свежие прокси от NodeMaven.
    """

    started = time.time()
    sess = _thread_local_sbis_session()

    def _do(proxy_url: str | None):
        proxies = None
        if proxy_url:
            proxies = {"http": proxy_url, "https": proxy_url}

        return sess.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            timeout=timeout,
            proxies=proxies,
            allow_redirects=allow_redirects,
        )

    # 1) Собираем кандидатов прокси на попытки
    candidates: list[str | None] = []

    if proxy_url_override:
        candidates.append(proxy_url_override)

        # порты для этого же proxy (быстро, без запроса в NodeMaven)
        ports = [8080, 8081, 8082, 8083, 8085, 8090, 8100]
        random.shuffle(ports)
        for p in ports:
            try:
                u = _replace_port_in_proxy_url(proxy_url_override, p)
                if u != proxy_url_override:
                    candidates.append(u)
            except Exception:
                continue

    # если inn задан — можно добрать “живых” прокси через warmup
    if inn:
        try:
            # хотим несколько штук, но быстро
            extra = warmup_good_proxies_for_inn(inn, want=5, total_budget_sec=12)
            for u in extra:
                if u and u not in candidates:
                    candidates.append(u)
        except Exception:
            pass

    # если вообще нет прокси и inn не задан — идём как есть (но в боевом пути у тебя inn всегда есть)
    if not candidates:
        candidates = [None]

    last_err: Exception | None = None
    last_bad_resp: requests.Response | None = None

    attempt = 0
    idx = 0
    while idx < len(candidates):
        proxy_url = candidates[idx]
        idx += 1
        attempt += 1

        # budget check
        if (time.time() - started) > total_budget_sec:
            break

        try:
            resp = _do(proxy_url)

            # если статус "плохой" — пробуем следующий прокси/порт
            if _is_retryable_http_status(resp.status_code) and (inn or proxy_url_override):
                body_snip = resp.text or ""
                if _is_revoked_or_untrusted_cert_response(body_snip):
                    # Может быть сертификат или регистрация клиента — в любом случае не ретраим
                    logger.warning(
                        "[SBIS_PROXY] no-retry error (cert/registration) — fail fast"
                    )
                    head = _short_body(resp)
                    code = resp.status_code
                    _close_http_response(last_bad_resp)
                    _close_http_response(resp)
                    raise CertInvalidNoRetryError(
                        f"Certificate invalid (no retry): status={code} "
                        f"body_head={head}"
                    )
                _close_http_response(last_bad_resp)
                last_bad_resp = resp
                logger.warning(
                    f"[SBIS_PROXY] retryable HTTP {resp.status_code} attempt={attempt} "
                    f"proxy={_mask_proxy_url(proxy_url) if proxy_url else None} "
                    f"body_head={_short_body(resp)}"
                )
                # при ошибке «Сертификат.ФИО/ИНН» — вывести в консоль тело ОТПРАВЛЕННОГО запроса
                if resp.status_code == 500 and "Сертификат.ФИО" in body_snip and "Сертификат.ИНН" in body_snip:
                    req_preview = _request_body_preview_for_log(data)
                    print("[SBIS_PROXY] >>> ТЕЛО ОТПРАВЛЕННОГО ЗАПРОСА (при ошибке ФИО/ИНН):", req_preview, flush=True)
                    logger.warning("[SBIS_PROXY] request body preview (ФИО/ИНН error): %s", req_preview[:500])
                continue

            _close_http_response(last_bad_resp)
            last_bad_resp = None
            return resp

        except CertInvalidNoRetryError:
            raise

        except (ProxyError, Timeout, ConnectionError, SSLError) as e:
            last_err = e
            logger.warning(
                f"[SBIS_PROXY] transport error attempt={attempt} proxy={_mask_proxy_url(proxy_url) if proxy_url else None}: {e}"
            )
            continue

        except Exception as e:
            last_err = e
            logger.warning(
                f"[SBIS_PROXY] unexpected error attempt={attempt} proxy={_mask_proxy_url(proxy_url) if proxy_url else None}: {e}"
            )
            continue

    # если дошли сюда — не вышло
    if last_bad_resp is not None:
        try:
            raise RuntimeError(
                f"Proxy/HTTP failed (budget={total_budget_sec}s): "
                f"last_status={last_bad_resp.status_code} "
                f"last_body_head={_short_body(last_bad_resp)}"
            )
        finally:
            _close_http_response(last_bad_resp)

    if last_err is not None:
        raise RuntimeError(f"Proxy/HTTP failed (budget={total_budget_sec}s): {last_err}")

    raise RuntimeError(
        f"Proxy/HTTP failed (budget={total_budget_sec}s): no response, attempts={attempt}, candidates={len(candidates)}"
    )


def _sbis_post(
    url: str,
    *,
    headers: dict,
    data: str,
    timeout: int = 30,
    inn: str | None = None,
    proxy_url_override: str | None = None,
    total_budget_sec: int = 45,
):
    return _sbis_request(
        "POST",
        url,
        headers=headers,
        data=data,
        timeout=timeout,
        inn=inn,
        proxy_url_override=proxy_url_override,
        total_budget_sec=total_budget_sec,
    )


def _sbis_get(
    url: str,
    *,
    headers: dict,
    timeout: int = 60,
    inn: str | None = None,
    proxy_url_override: str | None = None,
    total_budget_sec: int = 120,
):
    return _sbis_request(
        "GET",
        url,
        headers=headers,
        data=None,
        timeout=timeout,
        inn=inn,
        proxy_url_override=proxy_url_override,
        total_budget_sec=total_budget_sec,
    )


def run_cmd(args: list[str], timeout_sec: int = 90) -> str:
    """Запуск команды без доступа к stdin. certmgr/cryptcp при CSP_USE_SUDO вызываются через sudo."""
    if args and args[0] in (CERTMGR_BIN, CRYPTCP_BIN) and _csp_use_sudo():
        args = ["sudo", *args]
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip() or f"exit code {result.returncode}"
            raise RuntimeError(f"{args[0] if args else '?'}: {err}")
        return result.stdout or ""
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(
            f"Команда {args[0] if args else '?'} не завершилась за {timeout_sec} с (возможен запрос пароля или недоступный контейнер)"
        ) from e


def export_cert_der(csptest_name: str, dest_path: str) -> None:
    run_cmd([CERTMGR_BIN, "-export", "-cont", csptest_name, "-dest", dest_path])


def get_certmgr_list_file_output(cert_path: str) -> str:
    """Полный текст `certmgr -list -file` (SHA1, Subject и т.д.)."""
    return run_cmd([CERTMGR_BIN, "-list", "-file", cert_path])


def get_thumbprint_from_cert(cert_path: str) -> str:
    return get_thumbprint_from_certmgr_listing(get_certmgr_list_file_output(cert_path))


def get_thumbprint_from_certmgr_listing(out: str) -> str:
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SHA1 Thumbprint"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1].strip().lower()
    raise RuntimeError("Не удалось вытащить SHA1 Thumbprint из файла сертификата")


def get_fio_from_cert_file(cert_path: str) -> str:
    """
    Из вывода certmgr -list -file извлечь ФИО (значение CN из Subject/Субъект).
    Нужно для СБИС.АутентифицироватьПоСертификату при запросе через прокси (обязательные поля Сертификат.ФИО, Сертификат.ИНН).
    """
    try:
        out = get_certmgr_list_file_output(cert_path)
    except Exception:
        return ""
    subject = ""
    for line in out.splitlines():
        line_stripped = line.strip()
        if line_stripped.startswith("Subject:") or line_stripped.startswith("Субъект:"):
            subject = line_stripped.split(":", 1)[1].strip()
            break
    if not subject:
        return ""
    m = re.search(r"CN=([^,]+)", subject, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r"CN\s*=\s*([^,]+)", subject, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return subject[:200].strip()


# Порядок важен: явные KPP/КПП в Subject, затем OID КПП (ФНС) в квалифицированных сертах РФ.
_KPP_SUBJECT_RES = (
    re.compile(r"(?i)\bKPP=([0-9]{9})\b"),
    re.compile(r"КПП=([0-9]{9})"),
    re.compile(r"1\.2\.643\.100\.5=([0-9]{9})\b"),
)


def parse_kpp_from_subject_text(text: str) -> str | None:
    """Ищет КПП в строке Subject / выводе certmgr."""
    if not (text or "").strip():
        return None
    for rx in _KPP_SUBJECT_RES:
        m = rx.search(text)
        if m:
            return m.group(1)
    return None


def parse_kpp_from_cert_file(
    cert_path: str,
    *,
    certmgr_listing: str | None = None,
) -> str | None:
    """
    Пытается извлечь 9-значный КПП из экспортированного .cer:
    openssl x509 -subject (DER/PEM), затем certmgr -list -file (или готовый текст в certmgr_listing).
    """
    blobs: list[str] = []

    openssl_bin = shutil.which("openssl")
    if openssl_bin and os.path.isfile(cert_path):
        for inform in ("DER", "PEM"):
            try:
                r = subprocess.run(
                    [openssl_bin, "x509", "-inform", inform, "-in", cert_path, "-noout", "-subject"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    stdin=subprocess.DEVNULL,
                )
                if r.returncode == 0 and (r.stdout or "").strip():
                    blobs.append(r.stdout.strip())
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                break

    if certmgr_listing is not None:
        blobs.append(certmgr_listing)
    else:
        try:
            blobs.append(
                run_cmd([CERTMGR_BIN, "-list", "-file", cert_path], timeout_sec=60)
            )
        except Exception:
            pass

    return parse_kpp_from_subject_text("\n".join(blobs))


def log_http_exchange(prefix: str, url: str, req_headers: dict, req_body: str, resp: requests.Response) -> None:
    log_id = uuid.uuid4().hex[:8]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = LOG_DIR / f"{ts}_{prefix}_{log_id}.log"

    lines: list[str] = []
    lines.append(f"=== REQUEST {prefix} ===")
    lines.append(f"URL: {url}")
    lines.append("Headers:")
    for k, v in req_headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("Body:")
    lines.append(req_body)
    lines.append("")
    lines.append(f"=== RESPONSE {prefix} ===")
    lines.append(f"Status: {resp.status_code} {resp.reason}")
    lines.append("Headers:")
    for k, v in resp.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(f"Body (len={len(resp.text)}):")
    lines.append(resp.text)

    path.write_text("\n".join(lines), encoding="utf-8")


def auth_sbis_by_cert(
    cert_path: str,
    thumbprint: str,
    inn: str = "no_inn",
    *,
    proxy_url: str | None = None,
    timeout_sec: int = 30,
    total_budget_sec: int = 45,
) -> str:
    logger.info("[SBIS auth] 1/4 Чтение серта и подготовка запроса")
    with open(cert_path, "rb") as f:
        cert_der = f.read()
    cert_b64 = base64.b64encode(cert_der).decode("ascii")

    inn_val = (inn or "").strip() if inn else ""
    if not inn_val or inn_val == "no_inn":
        inn_val = ""
    fio = get_fio_from_cert_file(cert_path)
    fio_val = (fio or "—").strip() or "—"
    cert_params: dict = {
        "ДвоичныеДанные": cert_b64,
        "ИНН": inn_val,
        "ФИО": fio_val,
    }
    logger.info("[SBIS auth] Сертификат.ИНН=%r Сертификат.ФИО=%r", cert_params["ИНН"], (cert_params["ФИО"])[:60])

    req = {
        "jsonrpc": "2.0",
        "method": "СБИС.АутентифицироватьПоСертификату",
        "params": {"Сертификат": cert_params},
        "id": 1,
    }

    headers = {"Content-Type": "application/json-rpc;charset=utf-8"}
    req_json = json.dumps(req, ensure_ascii=False)

    logger.info("[SBIS auth] 2/4 Отправка HTTP POST в СБИС %s", AUTH_URL)
    resp = _sbis_request(
        "POST",
        AUTH_URL,
        inn=inn,
        headers=headers,
        data=req_json,
        timeout=max(8, int(timeout_sec)),
        proxy_url_override=proxy_url,   # pinned proxy if provided
        total_budget_sec=max(12, int(total_budget_sec)),
    )
    log_http_exchange("AUTH", AUTH_URL, headers, req_json, resp)

    logger.info("[SBIS auth] СБИС ответил: %s", resp.status_code)
    resp.raise_for_status()
    data = resp.json()

    if data.get("error"):
        err = data["error"]
        err_msg = (err.get("message") or err.get("details") or str(err)).lower()
        if (
            "отозван" in err_msg
            or "не является доверенным" in err_msg
            or "выберите другой сертификат" in err_msg
            or "просроченному сертификату" in err_msg
            or "аутентификация по просроченному" in err_msg
        ):
            try:
                tp = (thumbprint or "").strip().lower()
                if inn and inn != "no_inn" and tp:
                    deleted = Certificate.objects.filter(inn=inn, thumbprint=tp).delete()
                    if deleted[0]:
                        logger.warning(
                            "[SBIS auth] Сертификат отозван/просрочен/не доверенный — удалён из БД (inn=%s)",
                            inn,
                        )
            except Exception as e:
                logger.warning("[SBIS auth] Не удалось удалить сертификат из БД: %s", e)
        raise RuntimeError(f"JSON-RPC error при аутентификации: {data['error']}")

    enc_b64 = data.get("result")
    if not enc_b64:
        raise RuntimeError(f"СБИС не вернул result при аутентификации: {data}")

    enc_bin = base64.b64decode(enc_b64)
    enc_path = "/tmp/sbis_report_auth.enc"
    dec_path = "/tmp/sbis_report_auth.dec"

    logger.info("[SBIS auth] 3/4 Запись .enc, запуск cryptcp -decr (расшифровка)")
    with open(enc_path, "wb") as f:
        f.write(enc_bin)

    run_cmd([CRYPTCP_BIN, "-decr", *CRYPTCP_DECR_FLAGS, "-thumbprint", thumbprint, enc_path, dec_path])

    logger.info("[SBIS auth] 4/4 Чтение session_id из .dec")
    with open(dec_path, "rb") as f:
        session_id = f.read().decode("utf-8").strip()
    return session_id


def extract_our_org_from_nds_xml(xml_path: str) -> dict | None:
    """
    Из отчёта НДС (XML) достать нашу организацию: СвНП/НПЮЛ → ИНН, КПП, название.
    Возвращает {"inn": str, "kpp": str, "name": str} или None при ошибке/отсутствии блока.
    """
    if not xml_path or not os.path.isfile(xml_path):
        return None
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        doc = root.find("Документ")
        if doc is None:
            return None
        np = doc.find("СвНП/НПЮЛ")
        if np is None:
            return None
        inn = (np.attrib.get("ИННЮЛ") or "").strip()
        kpp = (np.attrib.get("КПП") or "").strip()
        name = (np.attrib.get("НаимОрг") or "").strip()
        if not inn or not kpp or len(kpp) != 9 or not kpp.isdigit():
            return None
        return {"inn": inn, "kpp": kpp, "name": name or f"ИНН {inn}"}
    except Exception:
        return None


def build_svedenia_from_xml(xml_path: str) -> tuple[dict, dict, str, str, str, str]:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    doc = root.find("Документ")
    if doc is None:
        raise RuntimeError("В XML не найден тег <Документ>")

    id_file = root.attrib.get("ИдФайл", "")
    format_version = root.attrib.get("ВерсФорм", "")
    guid = ""
    if "_" in id_file:
        parts = id_file.rsplit("_", 1)
        if len(parts) == 2:
            guid = parts[1]

    year = doc.attrib.get("ОтчетГод", "")
    period_code = doc.attrib.get("Период", "")
    nom_korr = doc.attrib.get("НомКорр", "0")
    kod_no = doc.attrib.get("КодНО", "")
    po_mestu = doc.attrib.get("ПоМесту", "")
    knd = doc.attrib.get("КНД", "120085")

    np = doc.find("СвНП/НПЮЛ")
    inn = ""
    kpp = ""
    name_full = ""
    if np is not None:
        inn = np.attrib.get("ИННЮЛ", "")
        kpp = np.attrib.get("КПП", "")
        name_full = np.attrib.get("НаимОрг", "")

    our_org = {
        "СвЮЛ": {
            "ИНН": inn,
            "КПП": kpp,
            "Название": name_full,
            "НазваниеПолное": name_full,
        }
    }

    sved = {
        "Ссылка": "",
        "Номер": "1",
        "Описание": {
            "ИмяФормы": "Декларация по налогу на добавленную стоимость",
            "КНДФормы": knd,
            "ВидДокумента": "Первичный",
            "НомерКорректировки": nom_korr,
            "НОПоМестуУчета": kod_no,
            "НОПоМестуНахождения": kod_no,
            "Период": [
                {
                    "Год": year,
                    "Код": period_code,
                    "ИдентификаторВложения": "",
                }
            ],
        },
        "Пакет": {
            "ВерсПрог": "1С:БУХГАЛТЕРИЯ 3.0.156.17",
            "СКЗИ": "КриптоПро CSP 5.0",
        },
        "НатуральныйИдентификатор": "",
        "ПрограммаФормированияОтчета": "1С:БУХГАЛТЕРИЯ",
    }

    return sved, our_org, kod_no, po_mestu, guid, format_version


def extract_guid_from_xml_idfile(xml_path: str) -> str:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    id_file = (root.attrib.get("ИдФайл") or "").strip()
    if not id_file:
        raise RuntimeError(f"В XML {xml_path} нет атрибута ИдФайл")

    guid = id_file.rsplit("_", 1)[-1].strip()

    try:
        uuid.UUID(guid)
    except Exception as e:
        raise RuntimeError(f"Некорректный GUID в ИдФайл='{id_file}' ({xml_path}): {e}")

    return guid.upper()


def sign_xml_if_needed(xml_path: str, sign_path: str | None, thumbprint: str) -> str:
    if sign_path and os.path.exists(sign_path):
        return sign_path

    out_sign = f"{xml_path}.sgn"
    run_cmd([CRYPTCP_BIN, "-sign", "-detached", "-der", *CRYPTCP_SIGN_FLAGS, "-thumbprint", thumbprint, xml_path])

    if not os.path.exists(out_sign):
        raise RuntimeError(f"Не удалось создать подпись {out_sign}")
    return out_sign


def _build_enclosure(
    file_path: str,
    sign_path: str,
    subtype: str,
    format_version: str,
    title: str,
    category: str = "Основное",
    ident: str | None = None,
) -> dict:
    with open(file_path, "rb") as f:
        content = f.read()
    with open(sign_path, "rb") as f:
        sign = f.read()

    content_b64 = base64.b64encode(content).decode("ascii")
    sign_b64 = base64.b64encode(sign).decode("ascii")
    file_name = os.path.basename(file_path)

    return {
        "Подтип": subtype,
        "Направление": "Исходящий",
        "Идентификатор": ident or "00000000-0000-0000-0000-000000000000",
        "ВерсияФормата": format_version,
        "ПодВерсияФормата": "",
        "Название": title,
        "Категория": category,
        "Файл": {
            "Имя": file_name,
            "ДвоичныеДанные": content_b64,
            "Подпись": [{"ДвоичныеДанные": sign_b64}],
        },
    }


def send_nds_extra(
    inn: str,
    xml_path: str,
    sign_path: str | None = None,
    book_paths: list[str] | None = None,
) -> dict:
    if not os.path.exists(xml_path):
        return {"success": False, "error": {"message": f"Файл сведений не найден: {xml_path}"}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert:
        return {"success": False, "error": {"message": "Не найден сертификат для ИНН"}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)

    try:
        sign_path_final = sign_xml_if_needed(xml_path, sign_path, thumbprint)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка подписи: {e}"}}

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}"}}

    try:
        sved, our_org, kod_no, po_mestu, guid, format_version = build_svedenia_from_xml(xml_path)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка разбора XML: {e}"}}

    subtype_nds = sved["Описание"]["КНДФормы"]

    used_idents: set[str] = set()
    file_id_map: dict[str, str] = {}
    all_files = [xml_path] + (book_paths or [])

    for file_path in all_files:
        if not os.path.exists(file_path):
            continue
        ident = extract_guid_from_xml_idfile(file_path)
        if ident in used_idents:
            ident = str(uuid.uuid4()).upper()
        used_idents.add(ident)
        file_id_map[file_path] = ident

    enclosures: list[dict] = []
    main_file_ident = file_id_map.get(xml_path, "")
    if sved.get("Описание", {}).get("Период"):
        sved["Описание"]["Период"][0]["ИдентификаторВложения"] = main_file_ident

    for file_path in all_files:
        ident = file_id_map[file_path]
        if file_path == xml_path:
            sp = sign_path_final
            category = "Основное"
            title = sved.get("Описание", {}).get("ИмяФормы") or "Отчет"
        else:
            sp = sign_xml_if_needed(file_path, None, thumbprint)
            category = "Приложение"
            title = f"Приложение {os.path.basename(file_path)}"

        enclosures.append(
            _build_enclosure(
                file_path=file_path,
                sign_path=sp,
                subtype=subtype_nds,
                format_version=format_version,
                title=title,
                category=category,
                ident=ident,
            )
        )

    file_name = os.path.basename(xml_path)
    doc = {
        "Название": f"Доп.листы книги продаж ({file_name})",
        "Идентификатор": guid.lower() or uuid.uuid4().hex,
        "Тип": "ОтчетФНС",
        "ПодТип": subtype_nds,
        "ДатаВремяСоздания": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Расширение": {"ИдентификаторКомплекта": guid or str(uuid.uuid4())},
        "НашаОрганизация": our_org,
        "Участники": {
            "Отправитель": our_org,
            "Получатель": {"ГосударственнаяИнспекция": kod_no},
            "КонечныйПолучатель": {"ГосударственнаяИнспекция": kod_no},
        },
        "Сведения": sved,
        "Вложение": enclosures,
        "Сертификат": {"Отпечаток": thumbprint, "Ключ": {"Тип": "Клиентский"}},
    }

    body = {"jsonrpc": "2.0", "method": "СБИС.ЗаписатьКомплект", "params": {"Документ": [doc]}, "id": 1}

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    body_json = json.dumps(body, ensure_ascii=False)
    resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=body_json, timeout=30)
    log_http_exchange("REC_COMP", REPORTING_URL, headers, body_json, resp)

    if resp.status_code != 200:
        return {"success": False, "error": {"message": f"HTTP {resp.status_code}", "raw": resp.text}}

    try:
        data = resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON: {e}", "raw": resp.text}}

    if data.get("error"):
        return {"success": False, "error": data["error"]}

    if not isinstance(data, dict) or not data.get("result") or not isinstance(data["result"], list) or not data["result"]:
        return {"success": False, "error": {"message": "Не удалось получить документ из ответа"}}

    today_str = datetime.now().strftime("%d.%m.%Y")
    list_body = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокДокументов",
        "params": {
            "Фильтр": {"Тип": "ОтчетФНС", "Направление": "Исходящий", "ДатаС": today_str, "ДатаПо": today_str}
        },
        "id": 1,
    }

    list_resp = _sbis_request(
        "POST",
        REPORTING_URL,
        inn=inn,
        headers=headers,
        data=json.dumps(list_body, ensure_ascii=False),
        timeout=30,
    )

    try:
        list_data = list_resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON: {e}", "raw": list_resp.text}}

    if not list_data.get("result") or not list_data["result"].get("Документ"):
        return {"success": False, "error": {"message": "Не удалось получить документ из исходящей почты"}}

    logger.info(f"Найденные документы: {list_data['result']['Документ']}")
    for d in list_data["result"]["Документ"]:
        logger.info(f"Документ: {d.get('Идентификатор')}, Статус: {d.get('Статус', 'N/A')}")

    docs = [d for d in list_data["result"]["Документ"] if d.get("Статус") not in ["Отправлен", "Обработан"]]
    if not docs:
        return {"success": False, "error": {"message": "Нет подходящих документов для отправки"}}
    sbis_doc_id = docs[0]["Идентификатор"]

    prep_body = {
        "jsonrpc": "2.0",
        "method": "СБИС.ПодготовитьДействие",
        "params": {
            "Документ": {
                "Идентификатор": sbis_doc_id,
                "Этап": {"Название": "Отправка", "Действие": {"Название": "Отправить", "Сертификат": {"Отпечаток": thumbprint}}},
            }
        },
        "id": 2,
    }

    prep_json = json.dumps(prep_body, ensure_ascii=False)
    prep_resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=prep_json, timeout=30)
    log_http_exchange("PREPARE", REPORTING_URL, headers, prep_json, prep_resp)

    if prep_resp.status_code != 200:
        return {"success": False, "error": {"message": f"HTTP {prep_resp.status_code} Prepare", "raw": prep_resp.text}}

    try:
        prep_data = prep_resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON: {e}", "raw": prep_resp.text}}

    if prep_data.get("error"):
        return {"success": False, "error": prep_data["error"]}

    attachments = []
    for file_path in all_files:
        if file_path not in file_id_map:
            continue
        file_ident = file_id_map[file_path]
        sig_path = f"{file_path}.sgn"
        try:
            run_cmd([CRYPTCP_BIN, "-sign", "-detached", "-der", *CRYPTCP_SIGN_FLAGS, "-thumbprint", thumbprint, file_path, sig_path])
            with open(sig_path, "rb") as f:
                sig_b64 = base64.b64encode(f.read()).decode("ascii")
            attachments.append({"Идентификатор": file_ident, "Подпись": [{"Файл": {"ДвоичныеДанные": sig_b64}}]})
        except Exception as e:
            return {"success": False, "error": {"message": f"Ошибка подписи {file_path}: {e}"}}

    exec_body = {
        "jsonrpc": "2.0",
        "method": "СБИС.ВыполнитьДействие",
        "params": {
            "Документ": {
                "Идентификатор": sbis_doc_id,
                "Этап": {
                    "Название": "Отправка",
                    "Действие": {"Название": "Отправить", "Сертификат": {"Отпечаток": thumbprint}},
                    "Вложение": attachments,
                },
            }
        },
        "id": 3,
    }

    exec_json = json.dumps(exec_body, ensure_ascii=False)
    exec_resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=exec_json, timeout=30)
    log_http_exchange("EXEC", REPORTING_URL, headers, exec_json, exec_resp)

    if exec_resp.status_code != 200:
        return {"success": False, "error": {"message": f"HTTP {exec_resp.status_code} Execute", "raw": exec_resp.text}}

    try:
        exec_data = exec_resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON: {e}", "raw": exec_resp.text}}

    if exec_data.get("error"):
        return {"success": False, "error": exec_data["error"]}

    return {"success": True, "result": exec_data}


def _b64_to_bytes(data_b64: str) -> bytes:
    if not data_b64:
        return b""

    s = str(data_b64).strip()

    if "," in s and "base64" in s[:100].lower():
        s = s.split(",", 1)[1].strip()

    s = s.replace("\ufeff", "")
    s = re.sub(r"\s+", "", s)

    s = s.replace("-", "+").replace("_", "/")

    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad

    try:
        return base64.b64decode(s, validate=True)
    except Exception as e:
        raise ValueError(f"Некорректный base64: {e}")


def _extract_idfile_from_xml_bytes(xml_bytes: bytes) -> str:
    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        raise RuntimeError(f"Не удалось распарсить XML: {e}")

    id_file = (root.attrib.get("ИдФайл") or "").strip()
    if not id_file:
        raise RuntimeError("В XML нет атрибута ИдФайл")
    return id_file


def _log_decoded_xml(inn: str, kind: str, xml_bytes: bytes) -> dict:
    meta: dict = {"kind": kind, "size": len(xml_bytes)}
    sha = hashlib.sha256(xml_bytes).hexdigest()
    meta["sha256_bytes"] = sha

    try:
        root = ET.fromstring(xml_bytes)
        meta["root_tag"] = root.tag
        meta["idfile"] = ((root.attrib.get("ИдФайл") or "").strip() or None)

        def _get_attr(path, attr):
            el = root.find(path)
            return None if el is None else el.attrib.get(attr)

        meta["nds_values"] = {
            "СумПУ_173.1": _get_attr("Документ/НДС/СумУплНП", "СумПУ_173.1"),
            "НалПУ164": _get_attr("Документ/НДС/СумУпл164", "НалПУ164"),
            "НалВосстОбщ": _get_attr("Документ/НДС/СумУпл164/СумНалОб", "НалВосстОбщ"),
            "НалБаза": _get_attr("Документ/НДС/СумУпл164/СумНалОб/РеалТов20", "НалБаза"),
            "СумНал": _get_attr("Документ/НДС/СумУпл164/СумНалОб/РеалТов20", "СумНал"),
            "НалПредНППриоб": _get_attr("Документ/НДС/СумУпл164/СумНалВыч", "НалПредНППриоб"),
            "НалВычОбщ": _get_attr("Документ/НДС/СумУпл164/СумНалВыч", "НалВычОбщ"),
        }
    except Exception as e:
        meta["xml_parse_error"] = str(e)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    rid = uuid.uuid4().hex[:8]
    safe_inn = inn or "no_inn"
    stem = f"{ts}_{safe_inn}_{kind}_{rid}_{sha[:12]}"

    xml_path = ONEC_DECODE_DIR / f"{stem}.xml"
    meta_path = ONEC_DECODE_DIR / f"{stem}.meta.json"

    xml_path.write_bytes(xml_bytes)
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    logger.info(f"[1C_DECODE] saved {kind}: {xml_path}")
    return meta


def _normalize_xml_filename_from_idfile(id_file: str) -> str:
    name = (id_file or "").strip()
    if not name:
        raise RuntimeError("Пустой ИдФайл (нельзя построить имя файла)")
    if not name.lower().endswith(".xml"):
        name += ".xml"
    return name


def _extract_book_names_from_main_xml(xml_bytes: bytes) -> tuple[str | None, str | None]:
    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        raise RuntimeError(f"Не удалось распарсить основной XML: {e}")

    doc = root.find("Документ")
    if doc is None:
        return None, None

    nds = doc.find("НДС")
    if nds is None:
        return None, None

    buy = nds.find("КнигаПокуп")
    sell = nds.find("КнигаПрод")

    buy_name = buy.attrib.get("НаимКнПок") if buy is not None else None
    sell_name = sell.attrib.get("НаимКнПрод") if sell is not None else None

    buy_name = (buy_name or "").strip() or None
    sell_name = (sell_name or "").strip() or None
    return buy_name, sell_name

def _extract_send_meta_from_exec(exec_data: dict) -> dict:
    """
    exec_data — это полный ответ JSON-RPC из СБИС.ВыполнитьДействие (то, что у тебя в exec_data).
    Возвращает sbis_doc_id, sent_at, sent_date.
    """
    meta = {"sbis_doc_id": None, "sent_at": None, "sent_date": None}

    try:
        r = (exec_data or {}).get("result") or {}
        meta["sbis_doc_id"] = (r.get("Идентификатор") or "").strip() or None

        events = r.get("Событие") or []
        for ev in events:
            grp = ev.get("Группа") or {}
            if grp.get("Название") == "Отправка" or grp.get("Описание") == "Отправлено":
                sent_at = (ev.get("ДатаВремя") or "").strip() or None
                meta["sent_at"] = sent_at
                if sent_at and len(sent_at) >= 10:
                    meta["sent_date"] = sent_at[:10]
                break

        if not meta["sent_date"]:
            ext = r.get("Расширение") or {}
            d = (ext.get("ДатаСоздания") or "").strip() or None
            meta["sent_date"] = d

    except Exception:
        pass

    return meta



def send_nds_extra_1c(
    inn: str,
    main_xml_b64: str,
    book_xml_b64_list: list[str] | None = None,
    validate_book_names: bool = True,
    dry_run: bool = False,
) -> tuple[int, dict]:
    cert = Certificate.objects.filter(inn=inn).first()
    if not cert:
        return 403, {"success": False, "comment": "Ошибка доступа: нет подписи по указанному ИНН"}
    if not getattr(cert, "csptest_name", None):
        return 401, {"success": False, "comment": "Указанный ИНН не имеет валидной подписи"}

    if not inn or not main_xml_b64:
        return 400, {
            "success": False,
            "comment": "Ошибка входных данных",
            "error": {"message": "Поля inn и main_xml_b64 обязательны"},
        }

    book_xml_b64_list = book_xml_b64_list or []

    if dry_run:
        try:
            main_bytes = _b64_to_bytes(main_xml_b64)
            try:
                _log_decoded_xml(inn=inn, kind="main_dry", xml_bytes=main_bytes)
            except Exception:
                logger.exception("[1C_DECODE] failed to log main_dry xml")

            main_idfile = _extract_idfile_from_xml_bytes(main_bytes)
            main_filename = _normalize_xml_filename_from_idfile(main_idfile)

            book_filenames: list[str] = []
            for idx, b64 in enumerate(book_xml_b64_list, start=1):
                if not b64:
                    continue
                b = _b64_to_bytes(b64)
                try:
                    _log_decoded_xml(inn=inn, kind=f"book#{idx}_dry", xml_bytes=b)
                except Exception:
                    logger.exception(f"[1C_DECODE] failed to log book#{idx}_dry xml")

                bid = _extract_idfile_from_xml_bytes(b)
                fname = _normalize_xml_filename_from_idfile(bid)
                book_filenames.append(fname)

            expected_buy, expected_sell = (None, None)
            if validate_book_names:
                expected_buy, expected_sell = _extract_book_names_from_main_xml(main_bytes)
                present = set(book_filenames)
                missing: list[str] = []
                if expected_buy and expected_buy not in present:
                    missing.append(expected_buy)
                if expected_sell and expected_sell not in present:
                    missing.append(expected_sell)
                if missing:
                    return 400, {
                        "success": False,
                        "comment": "Ошибка входных данных",
                        "error": {
                            "message": "Имена книг из основного XML не найдены среди переданных book-файлов",
                            "expected_missing": missing,
                            "expected_in_main": {"buy": expected_buy, "sell": expected_sell},
                            "received": sorted(present),
                        },
                    }

            return 200, {
                "success": True,
                "comment": "DRY_RUN: данные приняты и распарсены, отправка в СБИС пропущена",
                "parsed": {
                    "inn": inn,
                    "main": {"idfile": main_idfile, "filename": main_filename},
                    "books": book_filenames,
                    "expected_in_main": {"buy": expected_buy, "sell": expected_sell},
                },
            }

        except Exception as e:
            return 400, {"success": False, "comment": "Ошибка входных данных", "error": {"message": str(e)}}

    result = send_nds_extra_b64_autoname(
        inn=inn,
        main_xml_b64=main_xml_b64,
        book_xml_b64_list=book_xml_b64_list,
        validate_book_names=validate_book_names,
    )

    if isinstance(result, dict) and result.get("success") is True:
        try:
            exec_data = result.get("result") or {}
            meta = _extract_send_meta_from_exec(exec_data)
            result["send_meta"] = meta
        except Exception:
            logger.exception("Failed to extract send_meta from exec result")
        return 200, result

    if isinstance(result, dict) and _looks_like_sbis_error(result):
        return 404, {"success": False, "comment": "Ошибка при отправке в СБИС", "error": result.get("error")}

    return 400, {
        "success": False,
        "comment": "Ошибка входных данных",
        "error": (result.get("error") if isinstance(result, dict) else {"message": "Неизвестная ошибка"}),
    }


def _looks_like_sbis_error(result: dict) -> bool:
    err = result.get("error") if isinstance(result, dict) else None
    if not isinstance(err, dict):
        return False

    msg = str(err.get("message") or "")
    if any(k in err for k in ("raw", "code")):
        return True

    needles = (
        "СБИС",
        "JSON-RPC",
        "HTTP",
        "аутентификац",
        "ЗаписатьКомплект",
        "ПодготовитьДействие",
        "ВыполнитьДействие",
    )
    m_low = msg.lower()
    return any(n.lower() in m_low for n in needles)


def send_nds_extra_b64_autoname(
    inn: str,
    main_xml_b64: str,
    book_xml_b64_list: list[str] | None = None,
    validate_book_names: bool = True,
) -> dict:
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if not main_xml_b64:
        return {"success": False, "error": {"message": "main_xml_b64 обязателен"}}

    book_xml_b64_list = book_xml_b64_list or []

    try:
        main_bytes = _b64_to_bytes(main_xml_b64)
        try:
            _log_decoded_xml(inn=inn, kind="main", xml_bytes=main_bytes)
        except Exception:
            logger.exception("[1C_DECODE] failed to log main xml")
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка декодирования main_xml_b64: {e}"}}

    try:
        main_idfile = _extract_idfile_from_xml_bytes(main_bytes)
        main_filename = _normalize_xml_filename_from_idfile(main_idfile)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка чтения ИдФайл основного XML: {e}"}}

    books: list[tuple[str, bytes]] = []
    for idx, b64 in enumerate(book_xml_b64_list, start=1):
        if not b64:
            continue
        try:
            b = _b64_to_bytes(b64)
            try:
                _log_decoded_xml(inn=inn, kind=f"book#{idx}", xml_bytes=b)
            except Exception:
                logger.exception(f"[1C_DECODE] failed to log book#{idx}")

            bid = _extract_idfile_from_xml_bytes(b)
            fname = _normalize_xml_filename_from_idfile(bid)
            books.append((fname, b))
        except Exception as e:
            return {"success": False, "error": {"message": f"Ошибка книги #{idx}: {e}"}}

    if validate_book_names:
        try:
            expected_buy, expected_sell = _extract_book_names_from_main_xml(main_bytes)
        except Exception as e:
            return {"success": False, "error": {"message": str(e)}}

        actual_names = {name for name, _ in books}
        missing: list[str] = []
        if expected_buy and expected_buy not in actual_names:
            missing.append(expected_buy)
        if expected_sell and expected_sell not in actual_names:
            missing.append(expected_sell)

        if missing:
            return {
                "success": False,
                "error": {
                    "message": "Имена книг из основного XML не найдены среди переданных book-файлов",
                    "expected_missing": missing,
                    "received": sorted(actual_names),
                },
            }

    with tempfile.TemporaryDirectory(prefix=f"sbis_nds_extra_{inn}_") as tmpdir:
        xml_path = os.path.join(tmpdir, main_filename)
        with open(xml_path, "wb") as f:
            f.write(main_bytes)

        book_paths: list[str] = []
        used_names: set[str] = {main_filename.lower()}

        for name, content in books:
            name_l = name.lower()
            if name_l in used_names:
                return {"success": False, "error": {"message": f"Дублирующееся имя файла по ИдФайл: {name}"}}
            used_names.add(name_l)

            p = os.path.join(tmpdir, name)
            with open(p, "wb") as f:
                f.write(content)
            book_paths.append(p)

        return send_nds_extra(inn=inn, xml_path=xml_path, sign_path=None, book_paths=book_paths)


def _download_archive_zip(
    inn: str,
    session_id: str,
    archive_url: str,
    *,
    timeout: int = 30,
    total_budget_sec: int = 35,
) -> bytes:
    r = _sbis_get(
        archive_url,
        headers={"X-SBISSessionID": session_id},
        timeout=timeout,
        inn=inn,
        total_budget_sec=total_budget_sec,
    )
    if r.status_code != 200:
        raise RuntimeError(f"Не удалось скачать архив: HTTP {r.status_code}, body_head={r.text[:200]}")
    content = r.content or b""
    content_type = (r.headers.get("Content-Type") or "").strip()
    payload_kind = _detect_archive_payload_kind(content=content, content_type=content_type)
    if payload_kind != "zip":
        head_hex = (content[:16] or b"").hex() or "empty"
        raise RuntimeError(
            "Ответ по СсылкаНаАрхив не ZIP "
            f"(detected={payload_kind}, content_type={content_type or 'n/a'}, "
            f"content_length={len(content)}, head16_hex={head_hex})"
        )
    return content


def _detect_archive_payload_kind(content: bytes, content_type: str | None = None) -> str:
    """Определяет формат ответа по сигнатуре байтов + Content-Type."""
    ctype = (content_type or "").lower()
    head = content[:256]
    head_l = head.lower()

    if content.startswith(b"PK\x03\x04"):
        return "zip"
    if content.startswith(b"Rar!\x1a\x07\x00") or content.startswith(b"Rar!\x1a\x07\x01\x00"):
        return "rar"
    if content.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head_l.startswith(b"<?xml"):
        return "xml"
    if "text/html" in ctype or b"<html" in head_l or b"<!doctype html" in head_l:
        return "html"
    if "json" in ctype or head_l.startswith(b"{") or head_l.startswith(b"["):
        return "json"
    if not content:
        return "empty"
    return "unknown"


def _extract_receipt_pdf_from_zip(zip_bytes: bytes) -> bytes:
    """
    В твоём архиве "справка" — это единственный PDF, который НЕ в папке 'PDF/'.
    Берём строго его, и валимся, если найдено не ровно 1.
    """
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    names = zf.namelist()

    pdfs = [n for n in names if n.lower().endswith(".pdf")]
    receipt = [n for n in pdfs if not n.startswith("PDF/")]

    if len(receipt) != 1:
        raise RuntimeError(
            f"Ожидался ровно 1 файл справки (PDF не из папки PDF/). "
            f"found={len(receipt)} receipt={receipt} all_pdfs={pdfs}"
        )

    return zf.read(receipt[0])


def fetch_receipt_pdf_b64_from_archive(
    inn: str,
    sbis_doc_id: str,
    sent_date: str,
) -> dict:
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if not sbis_doc_id:
        return {"success": False, "error": {"message": "sbis_doc_id обязателен"}}
    if not sent_date:
        return {"success": False, "error": {"message": "sent_date обязателен (dd.mm.yyyy)"}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert:
        return {"success": False, "error": {"message": "Не найден сертификат для ИНН"}}
    if not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Указанный ИНН не имеет валидной подписи"}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}"}}

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    list_body = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокДокументов",
        "params": {
            "Фильтр": {
                "Тип": "ОтчетФНС",
                "Направление": "Исходящий",
                "ДатаС": sent_date,
                "ДатаПо": sent_date,
            }
        },
        "id": 1,
    }

    list_json = json.dumps(list_body, ensure_ascii=False)
    list_resp = _sbis_post(
        REPORTING_URL,
        headers=headers,
        data=list_json,
        timeout=30,
        inn=inn,
    )

    if list_resp.status_code != 200:
        return {"success": False, "error": {"message": f"HTTP {list_resp.status_code}", "raw": list_resp.text}}

    try:
        list_data = list_resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON: {e}", "raw": list_resp.text}}

    docs = (((list_data.get("result") or {}).get("Документ")) or [])
    doc = next((d for d in docs if d.get("Идентификатор") == sbis_doc_id), None)

    if not doc:
        return {
            "success": False,
            "error": {
                "message": "Документ не найден в исходящих за указанную дату",
                "sbis_doc_id": sbis_doc_id,
                "sent_date": sent_date,
                "found": len(docs),
            },
        }

    archive_url = (doc.get("СсылкаНаАрхив") or "").strip()
    if not archive_url:
        return {"success": False, "error": {"message": "В документе нет СсылкаНаАрхив", "sbis_doc_id": sbis_doc_id}}

    try:
        zip_bytes = _download_archive_zip(inn=inn, session_id=session_id, archive_url=archive_url)
        pdf_bytes = _extract_receipt_pdf_from_zip(zip_bytes)
        pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")
    except Exception as e:
        return {"success": False, "error": {"message": str(e), "sbis_doc_id": sbis_doc_id}}

    return {
        "success": True,
        "result": {
            "sbis_doc_id": sbis_doc_id,
            "sent_date": sent_date,
            "archive_url": archive_url,
            "pdf_filename": "receipt.pdf",
            "pdf_b64": pdf_b64,
        },
    }

def sbis_auth_session_for_inn(
    inn: str,
    *,
    prewarm_proxies: bool = True,
    proxy_want: int = 6,
    proxy_warmup_budget_sec: int = 14,
    auth_timeout_sec: int = 14,
    auth_budget_sec: int = 20,
) -> dict:
    """
    1) Берём сертификат из БД по ИНН
    2) Экспортим .cer
    3) Достаём thumbprint
    4) Получаем X-SBISSessionID через СБИС.АутентифицироватьПоСертификату
    """
    inn = (inn or "").strip()
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}

    cert = Certificate.objects.filter(inn=inn, is_active=True).first()
    if not cert:
        return {"success": False, "error": {"message": "Не найден активный сертификат для ИНН", "inn": inn}}

    if not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "У сертификата пустой csptest_name", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    try:
        export_cert_der(cert.csptest_name, cert_path)
        thumbprint = get_thumbprint_from_cert(cert_path)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка подготовки сертификата: {e}", "inn": inn}}

    candidates: list[str | None] = []
    prewarmed: list[str] = []

    if prewarm_proxies:
        try:
            prewarmed = warmup_good_proxies_for_inn(
                inn,
                want=max(1, int(proxy_want)),
                total_budget_sec=max(6, int(proxy_warmup_budget_sec)),
                per_probe_timeout=4.5,
            )
        except Exception:
            prewarmed = []

    if prewarmed:
        candidates.extend(prewarmed)

    cached_proxy = get_good_proxy_for_inn(inn)
    if cached_proxy and cached_proxy not in candidates:
        candidates.append(cached_proxy)

    # fallback: без pinned proxy, чтобы _sbis_request сам перебрал кандидатов
    candidates.append(None)

    auth_errors: list[str] = []
    for proxy in candidates:
        try:
            session_id = auth_sbis_by_cert(
                cert_path,
                thumbprint,
                inn=inn,
                proxy_url=proxy,
                timeout_sec=max(8, int(auth_timeout_sec)),
                total_budget_sec=max(12, int(auth_budget_sec)),
            )
            return {
                "success": True,
                "result": {
                    "inn": inn,
                    "cert_path": cert_path,
                    "thumbprint": thumbprint,
                    "session_id": session_id,
                    "proxy_used": _mask_proxy_url(proxy) if proxy else None,
                    "prewarmed_count": len(prewarmed),
                },
            }
        except Exception as e:
            auth_errors.append(str(e))
            continue

    return {
        "success": False,
        "error": {
            "message": "Ошибка аутентификации в СБИС: не удалось подобрать живой прокси",
            "inn": inn,
            "attempts": len(candidates),
            "prewarmed_count": len(prewarmed),
            "last_error": auth_errors[-1] if auth_errors else None,
        },
    }


def sbis_rpc(
    inn: str,
    session_id: str,
    method: str,
    params: dict,
    *,
    timeout: int = 45,
    total_budget_sec: int = 45,
) -> dict:
    """
    Универсальный JSON-RPC вызов в REPORTING_URL.
    Возвращает распарсенный JSON (dict). Ошибки СБИС не прячет — отдаёт как есть.
    """
    headers = {
        "Content-Type": "application/json-rpc;charset=utf-8",
        "X-SBISSessionID": session_id,
    }
    body = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    body_json = json.dumps(body, ensure_ascii=False)

    resp = _sbis_request(
        "POST",
        REPORTING_URL,
        inn=inn,
        headers=headers,
        data=body_json,
        timeout=timeout,
        total_budget_sec=total_budget_sec,
    )

    # если СБИС вернул HTML/редирект/что-то странное — пусть будет видно
    try:
        data = resp.json()
    except Exception:
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": "HTTP_NON_JSON",
                "message": f"HTTP {resp.status_code} non-json response",
                "details": (resp.text or "")[:1000],
            },
            "id": 1,
        }

    return data

def sbis_get_our_org_from_service_info(inn: str, session_id: str, target_inn: str) -> dict | None:
    """
    Достаёт из СБИС.ИнформацияОСлужебныхЭтапах объект нашей организации по ИНН.
    Возвращает объект НашаОрганизация (как в ответе СБИС) или None если не нашли.
    """
    data = sbis_rpc(
        inn=inn,
        session_id=session_id,
        method="СБИС.ИнформацияОСлужебныхЭтапах",
        params={},  # обычно без параметров
        timeout=45,
    )

    if data.get("error"):
        raise RuntimeError(f"СБИС.ИнформацияОСлужебныхЭтапах error: {data['error']}")

    result = data.get("result")
    if not isinstance(result, list):
        # иногда может вернуться не список — лучше сразу увидеть
        raise RuntimeError(f"Unexpected result type: {type(result)}; body={str(result)[:400]}")

    target_inn = (target_inn or "").strip()
    if not target_inn:
        return None

    for item in result:
        org = (item or {}).get("НашаОрганизация") or (item or {}).get("НашаОрганизация".lower()) or None
        # по факту в доке: массив со списком наших организаций — структура может быть как item.НашаОрганизация
        # но встречается и когда item сам = НашаОрганизация. Поэтому подстрахуемся:
        candidate = org if isinstance(org, dict) else (item if isinstance(item, dict) else None)
        if not isinstance(candidate, dict):
            continue

        svul = (candidate.get("СвЮЛ") or {})
        cand_inn = (svul.get("ИНН") or "").strip()
        if cand_inn == target_inn:
            return candidate

    return None


def sbis_list_organizations_from_service_info(
    inn: str,
    session_id: str,
    *,
    timeout: int = 45,
) -> dict:
    """
    СБИС.ИнформацияОСлужебныхЭтапах — разбор всех «наших организаций» из ответа.

    Возвращает dict:
      success: bool
      organizations: [{"inn", "kpp", "name", "raw": dict}, ...]  — по возможности
      error: {...} при ошибке RPC или неожиданной структуре
      raw_result_type: str — для отладки
    """
    data = sbis_rpc(
        inn=inn,
        session_id=session_id,
        method="СБИС.ИнформацияОСлужебныхЭтапах",
        params={},
        timeout=timeout,
    )

    if data.get("error"):
        return {
            "success": False,
            "organizations": [],
            "error": data["error"],
            "raw_result_type": None,
        }

    result = data.get("result")
    raw_type = type(result).__name__

    def _extract_svul_pairs(candidate: dict) -> list[tuple[dict, dict]]:
        """Вернуть пары (родительский объект, СвЮЛ) если есть."""
        out: list[tuple[dict, dict]] = []
        if not isinstance(candidate, dict):
            return out
        svul = candidate.get("СвЮЛ")
        if isinstance(svul, dict):
            out.append((candidate, svul))
        # иногда вложенность иная
        for key in ("НашаОрганизация", "Организация", "ЮЛ"):
            sub = candidate.get(key)
            if isinstance(sub, dict):
                s2 = sub.get("СвЮЛ")
                if isinstance(s2, dict):
                    out.append((sub, s2))
        return out

    organizations: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def _add_from_svul(parent: dict, svul: dict) -> None:
        i = (str(svul.get("ИНН") or "").strip(), str(svul.get("КПП") or "").strip())
        if not i[0] and not i[1]:
            return
        key = (i[0], i[1])
        if key in seen:
            return
        seen.add(key)
        organizations.append(
            {
                "inn": i[0],
                "kpp": i[1],
                "name": (
                    str(svul.get("Название") or svul.get("Наименование") or "").strip()
                ),
                "raw": parent,
            }
        )

    if isinstance(result, list):
        for item in result:
            if not isinstance(item, dict):
                continue
            org = item.get("НашаОрганизация")
            candidates: list[dict] = []
            if isinstance(org, dict):
                candidates.append(org)
            candidates.append(item)
            for cand in candidates:
                for parent, svul in _extract_svul_pairs(cand):
                    _add_from_svul(parent, svul)
    elif isinstance(result, dict):
        # единичный объект или обёртка
        for parent, svul in _extract_svul_pairs(result):
            _add_from_svul(parent, svul)
        for key in ("НашаОрганизация", "Документ", "Организации"):
            sub = result.get(key)
            if isinstance(sub, list):
                for el in sub:
                    if isinstance(el, dict):
                        for parent, svul in _extract_svul_pairs(el):
                            _add_from_svul(parent, svul)
            elif isinstance(sub, dict):
                for parent, svul in _extract_svul_pairs(sub):
                    _add_from_svul(parent, svul)
    else:
        return {
            "success": False,
            "organizations": [],
            "error": {
                "message": f"Неожиданный тип result: {raw_type}",
                "sample": str(result)[:500] if result is not None else "",
            },
            "raw_result_type": raw_type,
        }

    return {
        "success": True,
        "organizations": organizations,
        "error": None,
        "raw_result_type": raw_type,
    }


def _deep_walk_collect_svul(
    obj: object,
    organizations: list[dict],
    seen: set[tuple[str, str]],
) -> None:
    """Рекурсивно собрать СвЮЛ с ИНН/КПП из произвольного JSON (ответ СБИС)."""
    if isinstance(obj, dict):
        svul = obj.get("СвЮЛ")
        if isinstance(svul, dict):
            inn_v = str(svul.get("ИНН") or "").strip()
            kpp_v = str(svul.get("КПП") or "").strip()
            if inn_v or kpp_v:
                key = (inn_v, kpp_v)
                if key not in seen:
                    seen.add(key)
                    organizations.append(
                        {
                            "inn": inn_v,
                            "kpp": kpp_v,
                            "name": str(
                                svul.get("Название") or svul.get("Наименование") or ""
                            ).strip(),
                            "raw": svul,
                        }
                    )
        for v in obj.values():
            _deep_walk_collect_svul(v, organizations, seen)
    elif isinstance(obj, list):
        for x in obj:
            _deep_walk_collect_svul(x, organizations, seen)


def _filter_service_stages_our_org(
    inn: str,
    kpp: str,
    *,
    org_name: str = "",
    date_from: str,
    date_to: str,
    page_size: int = 50,
) -> dict:
    """Фильтр СБИС.СписокСлужебныхЭтапов (на многих контурах КПП в СвЮЛ обязателен)."""
    kpp = (kpp or "").strip()
    return {
        "Блокировать": "Да",
        "НашаОрганизация": {
            "СвЮЛ": {
                "ИНН": inn,
                "КПП": kpp,
                "Название": (org_name or "").strip(),
                "КодФилиала": "",
            }
        },
        "ТолькоОтчетность": "Да",
        "ТолькоЭДО": "Нет",
        "ДатаС": date_from,
        "ДатаПо": date_to,
        "Навигация": {"РазмерСтраницы": str(int(page_size))},
    }


def sbis_list_organizations_from_service_stages(
    inn: str,
    session_id: str,
    *,
    kpp: str | None = None,
    org_name: str = "",
    date_from: str | None = None,
    date_to: str | None = None,
    page_size: int = 50,
    timeout: int = 45,
) -> dict:
    """
    СБИС.СписокСлужебныхЭтапов + рекурсивный разбор СвЮЛ в ответе.

    На контурах СБИС КПП в фильтре часто обязателен («КПП должен быть заполнен»).
    Без kpp HTTP-запрос не выполняется — передайте КПП, возьмите из БД/серта/XML.
    """
    kpp = (kpp or "").strip()
    if not kpp:
        return {
            "success": False,
            "organizations": [],
            "error": {
                "message": "КПП обязателен для СписокСлужебныхЭтапов на этом контуре СБИС",
                "code": "KPP_REQUIRED",
                "hint": "Передайте kpp=, заполните Organization.kpp, или parse_kpp_from_cert_file()",
            },
            "raw_result_type": None,
            "source_method": "СписокСлужебныхЭтапов",
            "docs_count": None,
        }

    today = datetime.now()
    if not date_to:
        date_to = today.strftime("%d.%m.%Y")
    if not date_from:
        date_from = (today - timedelta(days=90)).strftime("%d.%m.%Y")

    filt = _filter_service_stages_our_org(
        inn,
        kpp,
        org_name=org_name,
        date_from=date_from,
        date_to=date_to,
        page_size=page_size,
    )
    data = sbis_rpc(
        inn=inn,
        session_id=session_id,
        method="СБИС.СписокСлужебныхЭтапов",
        params={"Фильтр": filt},
        timeout=timeout,
    )

    if data.get("error"):
        return {
            "success": False,
            "organizations": [],
            "error": data["error"],
            "raw_result_type": None,
            "source_method": "СписокСлужебныхЭтапов",
        }

    result = data.get("result")
    organizations: list[dict] = []
    seen: set[tuple[str, str]] = set()
    _deep_walk_collect_svul(result, organizations, seen)

    # как в sbis_list_organizations_from_service_info — без лишнего raw в slim
    slim = []
    for o in organizations:
        slim.append(
            {
                "inn": o["inn"],
                "kpp": o["kpp"],
                "name": o["name"],
            }
        )

    return {
        "success": True,
        "organizations": slim,
        "error": None,
        "raw_result_type": type(result).__name__,
        "source_method": "СписокСлужебныхЭтапов",
        "docs_count": len((result or {}).get("Документ") or [])
        if isinstance(result, dict)
        else None,
    }


def _build_service_stages_filter_minimal(
    inn: str,
    *,
    page_size: int = 20,
    block: bool = True,
    only_reporting: bool = True,
    only_edo: bool = False,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict:
    """
    Минимальный фильтр, чтобы СБИС не ругался и при этом не требовать от нас Billing/SPP.
    Если СБИС у тебя попросит больше реквизитов — расширим позже, но начнём так.
    """
    f = {
        "Блокировать": "Да" if block else "Нет",
        "НашаОрганизация": {"СвЮЛ": {"ИНН": inn}},
        "ТолькоОтчетность": "Да" if only_reporting else "Нет",
        "ТолькоЭДО": "Да" if only_edo else "Нет",
        "Навигация": {"РазмерСтраницы": str(int(page_size))},
    }
    if date_from:
        f["ДатаС"] = date_from
    if date_to:
        f["ДатаПо"] = date_to
    return {"Фильтр": f}


def sbis_list_service_stages(
    inn: str,
    *,
    kpp: str,
    org_name: str = "",
    billing_id: str | None = None,
    spp_id: str | None = None,
    date_from: str | None = None,   # "dd.mm.yyyy"
    date_to: str | None = None,     # "dd.mm.yyyy"
    page_size: int = 20,
    only_reporting: bool = True,
) -> dict:
    """
    1) Аутентификация по сертификату (СБИС.АутентифицироватьПоСертификату)
    2) СБИС.СписокСлужебныхЭтапов с фильтром по нашей организации

    КПП — передаём ВРУЧНУЮ.
    only_reporting: True — только отчётность; False — в т.ч. требования ФНС и др. служебные.
    """

    if not inn:
        return {"success": False, "error": {"message": "inn обязателен", "inn": inn}}

    kpp = (kpp or "").strip()
    if not kpp:
        return {"success": False, "error": {"message": "kpp обязателен (передай вручную)", "inn": inn}}

    # даты по умолчанию — последние 30 дней
    today = datetime.now()
    if not date_to:
        date_to = today.strftime("%d.%m.%Y")
    if not date_from:
        date_from = (today - timedelta(days=30)).strftime("%d.%m.%Y")

    # сертификат
    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumb = get_thumbprint_from_cert(cert_path)

    # авторизация
    try:
        session_id = auth_sbis_by_cert(cert_path, thumb, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}", "inn": inn}}

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    # НашаОрганизация
    our_org = {
        "СвЮЛ": {
            "ИНН": inn,
            "КПП": kpp,
            "Название": org_name or "",
            "КодФилиала": "",
        }
    }
    if billing_id:
        our_org["ИдентификаторБиллинга"] = str(billing_id)
    if spp_id:
        our_org["ИдентификаторСПП"] = str(spp_id)

    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокСлужебныхЭтапов",
        "params": {
            "Фильтр": {
                "Блокировать": "Да",
                "НашаОрганизация": our_org,
                "ТолькоОтчетность": "Да" if only_reporting else "Нет",
                "ТолькоЭДО": "Нет",
                "ДатаС": date_from,
                "ДатаПо": date_to,
                "Навигация": {"РазмерСтраницы": str(page_size)},
            }
        },
        "id": 0,
    }

    req_json = json.dumps(body, ensure_ascii=False)

    try:
        resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=req_json, timeout=45)

        if resp.status_code != 200:
            return {
                "success": False,
                "error": {
                    "message": f"HTTP {resp.status_code}",
                    "inn": inn,
                    "raw_head": (resp.text or "")[:500],
                },
            }

        data = resp.json()
        if data.get("error"):
            return {"success": False, "error": {"message": f"СБИС error: {data['error']}", "inn": inn}}

        result = data.get("result") or {}
        docs = (result.get("Документ") or [])

        # небольшой превью, чтоб глазами понимать что пришло
        preview = []
        for d in docs[:10]:
            stages = []
            for st in (d.get("Этап") or []):
                actions = []
                for a in (st.get("Действие") or []):
                    actions.append(
                        {
                            "name": a.get("Название"),
                            "need_decrypt": a.get("ТребуетРасшифровки"),
                            "need_sign": a.get("ТребуетПодписания"),
                            "sig_type": a.get("ТипПодписи"),
                        }
                    )
                stages.append(
                    {
                        "name": st.get("Название"),
                        "id": st.get("Идентификатор"),
                        "service": st.get("Служебный"),
                        "actions": actions,
                    }
                )

            preview.append(
                {
                    "id": d.get("Идентификатор"),
                    "name": d.get("Название"),
                    "type": d.get("Тип"),
                    "direction": d.get("Направление"),
                    "subtype": d.get("Подтип"),
                    "state": (d.get("Состояние") or {}).get("Код"),
                    "stages": stages,
                }
            )

        return {
            "success": True,
            "result": {
                "inn": inn,
                "kpp_used": kpp,
                "period": {"from": date_from, "to": date_to},
                "session_id_head": (session_id or "")[:8],
                "total_docs": len(docs),
                "docs": docs,
                "preview": preview,
                "raw_result_keys": list(result.keys()),
            },
        }

    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка СписокСлужебныхЭтапов: {e}", "inn": inn}}


def sbis_prepare_action(
    inn: str,
    *,
    kpp: str,
    doc_id: str,
    stage_id: str,
    action_name: str = "Обработать служебное",
    org_name: str = "",
    billing_id: str | None = None,
    spp_id: str | None = None,
) -> dict:
    """
    СБИС.ПодготовитьДействие для служебного этапа.
    Возвращает сырой ответ result, где обычно лежат Вложение (XML/PDF/DOC и т.п.)
    """

    if not inn:
        return {"success": False, "error": {"message": "inn обязателен", "inn": inn}}
    if not (kpp or "").strip():
        return {"success": False, "error": {"message": "kpp обязателен", "inn": inn}}
    if not (doc_id or "").strip():
        return {"success": False, "error": {"message": "doc_id обязателен", "inn": inn}}
    if not (stage_id or "").strip():
        return {"success": False, "error": {"message": "stage_id обязателен", "inn": inn}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumb = get_thumbprint_from_cert(cert_path)

    try:
        session_id = auth_sbis_by_cert(cert_path, thumb, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}", "inn": inn}}

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    fio = (get_fio_from_cert_file(cert_path) or "—").strip() or "—"

    our_org = {
        "СвЮЛ": {
            "ИНН": inn,
            "КПП": kpp,
            "Название": org_name or "",
            "КодФилиала": "",
        }
    }
    if billing_id:
        our_org["ИдентификаторБиллинга"] = str(billing_id)
    if spp_id:
        our_org["ИдентификаторСПП"] = str(spp_id)

    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.ПодготовитьДействие",
        "params": {
            "Документ": {
                "Идентификатор": doc_id,
                "НашаОрганизация": our_org,
                "Этап": {
                    "Идентификатор": stage_id,
                    "Действие": {
                        "Название": action_name,
                        "Сертификат": {"Отпечаток": thumb, "ИНН": inn, "ФИО": fio},
                    },
                },
            }
        },
        "id": 1,
    }

    req_json = json.dumps(body, ensure_ascii=False)

    try:
        resp = _sbis_request("POST", REPORTING_URL, inn=inn, headers=headers, data=req_json, timeout=45)
        if resp.status_code != 200:
            body_head = (resp.text or "").strip()[:400]
            return {
                "success": False,
                "error": {"message": f"HTTP {resp.status_code} при ПодготовитьДействие. Ответ: {body_head or '(пусто)'}", "inn": inn, "raw_head": body_head},
            }

        data = resp.json()
        if data.get("error"):
            return {"success": False, "error": {"message": f"СБИС error: {data['error']}", "inn": inn}}

        return {
            "success": True,
            "result": {
                "inn": inn,
                "kpp_used": kpp,
                "session_id": session_id,
                "thumbprint": thumb,
                "raw": data.get("result"),
            },
        }

    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка ПодготовитьДействие: {e}", "inn": inn}}


def sbis_download_stage_attachments(
    inn: str,
    *,
    session_id: str,
    prepared_raw: dict | list | None,
    max_files: int = 10,
) -> dict:
    """
    Из result СБИС.ПодготовитьДействие достаёт вложения и скачивает их.
    Поддерживает:
    - Файл.ДвоичныеДанные (base64)
    - Файл.Ссылка (скачиваем по GET с X-SBISSessionID)
    """

    if not prepared_raw:
        return {"success": False, "error": {"message": "prepared_raw пустой"}}

    def _iter_attachments(raw_obj):
        # В реальности СБИС может вернуть dict/ list — делаем мягко.
        if isinstance(raw_obj, dict):
            # иногда вложения лежат прямо в raw_obj["Этап"]["Вложение"]
            etap = raw_obj.get("Этап") if isinstance(raw_obj.get("Этап"), dict) else None
            if etap and isinstance(etap.get("Вложение"), list):
                for v in etap["Вложение"]:
                    yield v
            # иногда "Документ" список
            if isinstance(raw_obj.get("Документ"), list):
                for d in raw_obj["Документ"]:
                    etap2 = d.get("Этап") if isinstance(d.get("Этап"), dict) else None
                    if etap2 and isinstance(etap2.get("Вложение"), list):
                        for v in etap2["Вложение"]:
                            yield v
            return

        if isinstance(raw_obj, list):
            for x in raw_obj:
                yield from _iter_attachments(x)

    files = []
    count = 0

    for att in _iter_attachments(prepared_raw):
        if count >= max_files:
            break

        f = (att or {}).get("Файл") or {}
        name = (f.get("Имя") or f.get("Название") or f.get("Файл") or "").strip() or None
        href = (f.get("Ссылка") or "").strip() or None
        b64 = (f.get("ДвоичныеДанные") or "").strip() or None

        content = b""
        source = None

        try:
            if b64:
                content = base64.b64decode(b64)
                source = "b64"
            elif href:
                r = _sbis_get(href, headers={"X-SBISSessionID": session_id}, timeout=60, inn=inn)
                if r.status_code != 200:
                    files.append(
                        {
                            "name": name,
                            "href": href,
                            "ok": False,
                            "error": f"download HTTP {r.status_code} body_head={(r.text or '')[:200]}",
                        }
                    )
                    continue
                content = r.content or b""
                source = "link"
            else:
                files.append({"name": name, "ok": False, "error": "нет ни ДвоичныеДанные, ни Ссылка"})
                continue

            files.append(
                {
                    "name": name,
                    "href": href,
                    "ok": True,
                    "source": source,
                    "size": len(content),
                    "bytes": content,
                }
            )
            count += 1

        except Exception as e:
            files.append({"name": name, "href": href, "ok": False, "error": str(e)})

    return {"success": True, "result": {"files": files}}


def sbis_decrypt_bytes_with_cert_thumbprint(
    enc_bytes: bytes,
    *,
    thumbprint: str,
    inn: str = "no_inn",
    suffix: str = "sbis_dec",
) -> bytes:
    """
    Расшифровывает байты через cryptcp -decr -thumbprint <thumb>.
    СБИС шлёт зашифрованный файл — надо прогнать через закрытый ключ.
    """

    if not enc_bytes:
        raise RuntimeError("enc_bytes пустой")
    if not (thumbprint or "").strip():
        raise RuntimeError("thumbprint пустой")

    with tempfile.TemporaryDirectory(prefix=f"{suffix}_{inn}_") as td:
        enc_path = os.path.join(td, "in.enc")
        dec_path = os.path.join(td, "out.dec")

        with open(enc_path, "wb") as f:
            f.write(enc_bytes)

        run_cmd([CRYPTCP_BIN, "-decr", *CRYPTCP_DECR_FLAGS, "-thumbprint", thumbprint, enc_path, dec_path])

        out = Path(dec_path).read_bytes()
        return out


def fetch_requirement_decrypted_preview(
    inn: str,
    *,
    kpp: str,
    requirement_doc_id: str,
    requirement_stage_id: str,
    org_name: str = "",
    max_preview_chars: int = 1200,
) -> dict:
    """
    Минимальный рабочий шаг:
      - auth
      - ПодготовитьДействие по stage_id
      - скачать вложения (disk.sbis.ru)
      - если Зашифрован=Да — попытаться расшифровать
      - отдать превью (название/размер/тип/кусок XML если это XML)
    """

    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if not kpp:
        return {"success": False, "error": {"message": "kpp обязателен"}}
    if not requirement_doc_id:
        return {"success": False, "error": {"message": "requirement_doc_id обязателен"}}
    if not requirement_stage_id:
        return {"success": False, "error": {"message": "requirement_stage_id обязателен"}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден валидный сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации: {e}", "inn": inn}}

    # 1) ПодготовитьДействие
    prep = sbis_prepare_action(
        inn,
        kpp=kpp,
        org_name=org_name,
        doc_id=requirement_doc_id,
        stage_id=requirement_stage_id,
    )
    if not prep.get("success"):
        return prep

    prepared_raw = ((prep.get("result") or {}).get("raw") or {})
    files_meta = _extract_files_from_prepare_raw(prepared_raw)

    # 2) Скачивание + (опционально) расшифровка
    files_preview = []
    for f in files_meta:
        name = (f.get("name") or "").strip() or None
        href = (f.get("href") or "").strip() or None
        encrypted_flag = f.get("encrypted")

        if not href:
            files_preview.append(
                {
                    "name": name,
                    "href": href,
                    "ok": False,
                    "error": "нет ссылки Файл.Ссылка",
                    "encrypted": encrypted_flag,
                }
            )
            continue

        try:
            content, dl_meta = sbis_download_file_by_link(inn, session_id=session_id, href=href)

            # если СБИС сказал, что зашифрован — пробуем decrypt
            if str(encrypted_flag).strip() == "Да":
                content2, dec_meta = _try_decrypt_bytes_with_cert(inn=inn, thumbprint=thumbprint, content=content)
            else:
                content2, dec_meta = content, {"decrypt_ok": False, "decrypt_error": None}

            # превью текста (если похоже на xml)
            text_preview = None
            low_name = (name or "").lower()
            if low_name.endswith(".xml") or (content2[:50].lstrip().startswith(b"<?xml") or content2[:20].lstrip().startswith(b"<")):
                # пробуем основные кодировки
                decoded = None
                for enc in ("windows-1251", "utf-8", "utf-16"):
                    try:
                        decoded = content2.decode(enc)
                        break
                    except Exception:
                        continue
                if decoded is None:
                    decoded = content2.decode("utf-8", errors="ignore")

                decoded = decoded.strip()
                text_preview = decoded[:max_preview_chars]

            files_preview.append(
                {
                    "name": name,
                    "href": href,
                    "ok": True,
                    "size": len(content2),
                    "content_type": dl_meta.get("content_type"),
                    "encrypted": encrypted_flag,
                    "decrypt_ok": dec_meta.get("decrypt_ok"),
                    "decrypt_error": dec_meta.get("decrypt_error"),
                    "text_preview": text_preview,
                }
            )

        except Exception as e:
            files_preview.append(
                {
                    "name": name,
                    "href": href,
                    "ok": False,
                    "error": str(e),
                    "encrypted": encrypted_flag,
                }
            )

    return {
        "success": True,
        "result": {
            "inn": inn,
            "kpp_used": kpp,
            "requirement_doc_id": requirement_doc_id,
            "requirement_stage_id": requirement_stage_id,
            "files_found": len(files_meta),
            "files_preview": files_preview,
        },
    }


def _extract_files_from_prepare_raw(prepared_raw: dict) -> list[dict]:
    """
    prepared_raw — это dict из (prep["result"]["raw"]).

    Возвращает список файлов:
      [{"name": str|None, "href": str|None, "sha1": str|None, "encrypted": str|None}, ...]
    """
    files: list[dict] = []

    if not isinstance(prepared_raw, dict):
        return files

    stages = prepared_raw.get("Этап")
    if not isinstance(stages, list):
        return files

    for st in stages:
        if not isinstance(st, dict):
            continue

        влож = st.get("Вложение") or st.get("Вложения")
        if not isinstance(влож, list):
            continue

        for att in влож:
            if not isinstance(att, dict):
                continue

            f = att.get("Файл")
            if not isinstance(f, dict):
                continue

            files.append(
                {
                    "name": (f.get("Имя") or f.get("Название") or att.get("Название") or None),
                    "href": (f.get("Ссылка") or None),
                    "sha1": (f.get("Хеш") or f.get("ХешСумма") or None),
                    "encrypted": (att.get("Зашифрован") or None),
                }
            )

    return files


def sbis_download_file_by_link(
    inn: str,
    *,
    session_id: str,
    href: str,
    timeout: int = 90,
) -> tuple[bytes, dict]:
    """
    Скачивает файл по ссылке (в т.ч. disk.sbis.ru) через прокси NodeMaven.
    Возвращает (bytes, meta).
    """
    if not href:
        raise RuntimeError("Пустая ссылка на файл")

    headers = {"X-SBISSessionID": session_id}

    r = _sbis_get(
        href,
        headers=headers,
        timeout=timeout,
        inn=inn,
    )

    # disk.sbis.ru может отдавать JSON с ошибкой, поэтому сохраняем head
    body_head = ""
    try:
        body_head = (r.text or "")[:200]
    except Exception:
        body_head = "<binary>"

    if r.status_code != 200:
        raise RuntimeError(f"Не удалось скачать файл: HTTP {r.status_code}, body_head={body_head}")

    content = r.content or b""

    meta = {
        "href": href,
        "http_status": r.status_code,
        "content_len": len(content),
        "content_type": r.headers.get("Content-Type"),
        "body_head": body_head,
    }
    return content, meta

def _try_decrypt_bytes_with_cert(
    *,
    inn: str,
    thumbprint: str,
    content: bytes,
) -> tuple[bytes, dict]:
    """
    Пытается расшифровать content через cryptcp -decr.
    Если не получилось — вернет исходный content, но в meta будет decrypt_ok=False.
    """
    meta = {"decrypt_ok": False, "decrypt_error": None}

    if not content:
        return content, meta

    with tempfile.TemporaryDirectory(prefix=f"sbis_dec_{inn}_") as td:
        in_path = os.path.join(td, "in.bin")
        out_path = os.path.join(td, "out.bin")

        with open(in_path, "wb") as f:
            f.write(content)

        try:
            run_cmd([CRYPTCP_BIN, "-decr", *CRYPTCP_DECR_FLAGS, "-thumbprint", thumbprint, in_path, out_path])
            dec = Path(out_path).read_bytes()
            meta["decrypt_ok"] = True
            return dec, meta
        except Exception as e:
            meta["decrypt_error"] = str(e)
            return content, meta

def sbis_list_changes(
    inn: str,
    *,
    kpp: str,
    requirement_doc_id: str,
    org_name: str = "",
    page_size: int = 50,
) -> dict:
    """
    СБИС.СписокИзменений — возвращает расшифрованные файлы/события по требованию.
    ВАЖНО: метод ожидает params.Фильтр (иначе "В объекте нет поля Фильтр").
    """
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if not kpp:
        return {"success": False, "error": {"message": "kpp обязателен"}}
    if not requirement_doc_id:
        return {"success": False, "error": {"message": "requirement_doc_id обязателен"}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден валидный сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации: {e}", "inn": inn}}

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.СписокИзменений",
        "params": {
            "Фильтр": {
                "Документ": {"Идентификатор": requirement_doc_id},
                "НашаОрганизация": {"СвЮЛ": {"ИНН": inn, "КПП": kpp, "Название": (org_name or "")}},
                "Навигация": {"РазмерСтраницы": str(page_size)},
            }
        },
        "id": 1,
    }

    try:
        resp = _sbis_post(
            REPORTING_URL,
            headers=headers,
            data=json.dumps(body, ensure_ascii=False),
            timeout=45,
            inn=inn,
        )
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка запроса в СБИС: {e}", "inn": inn}}

    if resp.status_code != 200:
        return {"success": False, "error": {"message": f"HTTP {resp.status_code}", "raw": resp.text}}

    try:
        data = resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка парсинга JSON: {e}", "raw": resp.text}}

    if data.get("error"):
        return {"success": False, "error": data["error"]}

    result = data.get("result") or {}

    # аккуратный превью по тому, что пришло
    events = result.get("Событие") or []
    preview = []
    if isinstance(events, list):
        for ev in events[:20]:
            if not isinstance(ev, dict):
                continue
            влож = ev.get("Вложение") or []
            preview.append(
                {
                    "event_name": (ev.get("Название") or ""),
                    "event_time": (ev.get("ДатаВремя") or ev.get("Дата") or ""),
                    "attachments": len(влож) if isinstance(влож, list) else 0,
                }
            )

    return {
        "success": True,
        "result": {
            "inn": inn,
            "kpp_used": kpp,
            "requirement_doc_id": requirement_doc_id,
            "events_count": len(events) if isinstance(events, list) else None,
            "events_preview": preview,
            "raw": result,
        },
    }

def fetch_requirement_file_b64(
    inn: str,
    *,
    kpp: str,
    requirement_doc_id: str,
    requirement_stage_id: str,
    action_name: str = "Обработать служебное",
    save_to: str | None = None,  # например "/tmp/requirement.pdf"
) -> dict:
    """
    Возвращает base64 РАСШИФРОВАННОГО файла требования (обычно PDF),
    используя inn/kpp/doc_id/stage_id.

    Важно: для СБИС.ПодготовитьДействие нужно указать Этап.Действие.Название,
    иначе будет "Не указано название действия".

    Скачивание по «Ссылка» должно идти с тем же X-SBISSessionID, что и после auth;
    ответ 403 (в т.ч. с текстом про HMAC/доступ) часто даёт СБИС при другом exit-IP
    или без сессии — ретраи HTTP перебирают прокси из пула (_sbis_request).
    """
    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    if not kpp:
        return {"success": False, "error": {"message": "kpp обязателен"}}
    if not requirement_doc_id:
        return {"success": False, "error": {"message": "requirement_doc_id обязателен"}}
    if not requirement_stage_id:
        return {"success": False, "error": {"message": "requirement_stage_id обязателен"}}
    if not action_name:
        return {"success": False, "error": {"message": "action_name обязателен (например 'Обработать служебное')"}}

    cert = Certificate.objects.filter(inn=inn).first()
    if not cert or not getattr(cert, "csptest_name", None):
        return {"success": False, "error": {"message": "Не найден валидный сертификат для ИНН", "inn": inn}}

    cert_path = f"/tmp/sbis_report_{inn}.cer"
    export_cert_der(cert.csptest_name, cert_path)
    thumbprint = get_thumbprint_from_cert(cert_path)

    try:
        session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка аутентификации в СБИС: {e}", "inn": inn}}

    fio = (get_fio_from_cert_file(cert_path) or "—").strip() or "—"

    # 1) ПодготовитьДействие — чтобы получить вложение и ссылку (Сертификат внутри Действие, как в Отправить)
    body = {
        "jsonrpc": "2.0",
        "method": "СБИС.ПодготовитьДействие",
        "params": {
            "Документ": {
                "Идентификатор": requirement_doc_id,
                "Этап": {
                    "Идентификатор": requirement_stage_id,
                    "Действие": {
                        "Название": action_name,
                        "Сертификат": {"Отпечаток": thumbprint, "ИНН": inn, "ФИО": fio},
                    },
                },
            }
        },
        "id": 1,
    }

    headers = {"Content-Type": "application/json-rpc;charset=utf-8", "X-SBISSessionID": session_id}

    try:
        resp = _sbis_post(
            REPORTING_URL,
            headers=headers,
            data=json.dumps(body, ensure_ascii=False),
            timeout=45,
            inn=inn,
        )
    except Exception as e:
        return {"success": False, "error": {"message": f"Ошибка СБИС.ПодготовитьДействие: {e}", "inn": inn}}

    if resp.status_code != 200:
        body_head = (resp.text or "").strip()[:400]
        return {
            "success": False,
            "error": {
                "message": f"HTTP {resp.status_code} при ПодготовитьДействие. Ответ: {body_head or '(пусто)'}",
                "body_head": body_head,
            },
        }

    try:
        data = resp.json()
    except Exception as e:
        return {"success": False, "error": {"message": f"Не смог распарсить JSON ПодготовитьДействие: {e}", "raw": resp.text[:300]}}

    if data.get("error"):
        return {"success": False, "error": {"message": f"JSON-RPC error ПодготовитьДействие: {data['error']}", "inn": inn}}

    raw = data.get("result") or {}
    stages = raw.get("Этап") or []
    if not isinstance(stages, list) or not stages:
        return {"success": False, "error": {"message": "В ответе нет Этап[]", "inn": inn, "keys": list(raw.keys())}}

    st0 = stages[0] or {}
    atts = st0.get("Вложение") or []
    if not isinstance(atts, list) or not atts:
        return {"success": False, "error": {"message": "В ответе нет Этап[0].Вложение[]", "inn": inn}}

    # По доке СБИС: два вложения — XML обмена и требование в формате PDF или DOC. Скачиваем все и отдаём первое (для обратной совместимости).
    attachments_out: list[dict] = []
    for i, att in enumerate(atts):
        att = att or {}
        file_obj = att.get("Файл") or {}
        if not isinstance(file_obj, dict):
            continue
        file_url = (file_obj.get("Ссылка") or "").strip()
        filename = (file_obj.get("Имя") or file_obj.get("Название") or "requirement.bin").strip()
        if not file_url:
            continue
        if i > 0:
            time.sleep(1.0)  # пауза между вложениями
        encrypted_flag = (att.get("Зашифрован") or "").strip()
        try:
            r = _sbis_get(
                file_url,
                headers={"X-SBISSessionID": session_id},
                timeout=120,
                inn=inn,
                total_budget_sec=180,
            )
        except Exception as e:
            return {"success": False, "error": {"message": f"Ошибка скачивания вложения {i + 1}: {e}", "url": file_url}}
        if r.status_code == 403:
            time.sleep(2.0)
            try:
                r = _sbis_get(
                    file_url,
                    headers={"X-SBISSessionID": session_id},
                    timeout=120,
                    inn=inn,
                    total_budget_sec=180,
                )
            except Exception as e:
                return {"success": False, "error": {"message": f"Ошибка повтора скачивания вложения {i + 1}: {e}", "url": file_url}}
        if r.status_code != 200:
            return {
                "success": False,
                "error": {"message": f"HTTP {r.status_code} при скачивании вложения {i + 1}", "url": file_url},
            }
        content = r.content or b""
        decrypted = content
        if encrypted_flag == "Да":
            try:
                with tempfile.TemporaryDirectory(prefix=f"sbis_req_dec_{inn}_") as td:
                    enc_path = os.path.join(td, f"req_{i}.enc")
                    dec_path = os.path.join(td, f"req_{i}.dec")
                    Path(enc_path).write_bytes(content)
                    run_cmd([CRYPTCP_BIN, "-decr", *CRYPTCP_DECR_FLAGS, "-thumbprint", thumbprint, enc_path, dec_path])
                    decrypted = Path(dec_path).read_bytes()
            except Exception:
                decrypted = content
        is_pdf = decrypted.startswith(b"%PDF") or (filename or "").lower().endswith(".pdf")
        is_doc = (filename or "").lower().endswith((".doc", ".docx"))
        attachments_out.append({
            "filename": filename,
            "b64": base64.b64encode(decrypted).decode("ascii"),
            "size": len(decrypted),
            "is_pdf": is_pdf,
            "is_doc": is_doc,
        })

    if not attachments_out:
        return {"success": False, "error": {"message": "Не удалось скачать ни одного вложения", "inn": inn}}

    # Выбираем вложение: предпочитаем PDF, затем DOC, иначе первое
    chosen = None
    for a in attachments_out:
        if a["is_pdf"] or a["is_doc"]:
            chosen = a
            break
    if not chosen:
        chosen = attachments_out[0]

    saved_to = None
    if save_to:
        try:
            Path(save_to).parent.mkdir(parents=True, exist_ok=True)
            Path(save_to).write_bytes(base64.b64decode(chosen["b64"]))
            saved_to = save_to
        except Exception:
            pass

    return {
        "success": True,
        "result": {
            "inn": inn,
            "kpp_used": kpp,
            "requirement_doc_id": requirement_doc_id,
            "requirement_stage_id": requirement_stage_id,
            "action_name": action_name,
            "filename": chosen["filename"],
            "size": chosen["size"],
            "saved_to": saved_to,
            "b64": chosen["b64"],
            "attachments_count": len(attachments_out),
            "attachments_all": attachments_out,
        },
    }


def _extract_xml_files_from_zip(zip_bytes: bytes) -> list[tuple[str, bytes]]:
    """
    Возвращает все XML-файлы из zip-архива СБИС.
    """
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    out: list[tuple[str, bytes]] = []
    for name in zf.namelist():
        if not name.lower().endswith(".xml"):
            continue
        try:
            out.append((name, zf.read(name)))
        except Exception:
            logger.exception("Не удалось прочитать XML %s из архива", name)
    return out


def _local_xml_tag(tag: str) -> str:
    if not isinstance(tag, str):
        return ""
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _collect_sales_book_rows(
    xml_bytes: bytes,
    *,
    counterparty_id: str | None = None,
    max_rows: int = 500,
) -> dict:
    """
    Возвращает строки/узлы книги продаж (раздел 9).
    - если counterparty_id передан: фильтр по контрагенту
    - если counterparty_id пустой: возвращаем все строки раздела 9
    """
    target = (counterparty_id or "").strip()

    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        return {"total_rows": 0, "rows": [], "xml_parse_error": str(e)}

    rows: list[dict] = []
    xml_hits = 0

    sales_hints = ("КнигаПрод", "КнПрод", "Разд9", "Продаж")
    counterparty_attr_hints = ("ИНН", "Ид", "Идентификатор", "Покуп")

    def walk(node: ET.Element, path: list[str]) -> None:
        nonlocal xml_hits
        current_tag = _local_xml_tag(node.tag)
        current_path = path + [current_tag]

        attrs = {str(k): str(v) for k, v in (node.attrib or {}).items()}
        path_str = "/".join(current_path)

        in_sales_section = any(h.lower() in path_str.lower() for h in sales_hints)
        if in_sales_section:
            match_by_counterparty = False
            if target:
                for k, v in attrs.items():
                    key_ok = any(h.lower() in k.lower() for h in counterparty_attr_hints)
                    if key_ok and v.strip() == target:
                        match_by_counterparty = True
                        break
            else:
                # Когда контрагент не задан, возвращаем узлы раздела 9,
                # где есть полезные атрибуты (обычно строки/записи книги продаж).
                match_by_counterparty = bool(attrs)

            if match_by_counterparty:
                xml_hits += 1
                if len(rows) < max_rows:
                    rows.append(
                        {
                            "tag": current_tag,
                            "path": path_str,
                            "attrs": attrs,
                        }
                    )

        for ch in list(node):
            walk(ch, current_path)

    walk(root, [])

    return {
        "total_rows": xml_hits,
        "rows": rows,
    }


def fetch_sales_book_extract_by_counterparty(
    inn: str,
    *,
    counterparty_id: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    sbis_doc_id: str | None = None,
    nds_subtype: str | None = None,
    max_docs: int = 30,
    rpc_timeout_sec: int = 25,
    rpc_budget_sec: int = 30,
    archive_timeout_sec: int = 20,
    archive_budget_sec: int = 25,
    auth_timeout_sec: int = 14,
    auth_budget_sec: int = 20,
    proxy_prewarm_count: int = 6,
) -> dict:
    """
    Получение выписки книги продаж по контрагенту через API СБИС.

    Используемый endpoint: https://online.sbis.ru/service/?srv=1
    Используемый метод JSON-RPC: СБИС.СписокДокументов

    Дальше берём СсылкаНаАрхив у документа, читаем XML и фильтруем раздел 9 (книга продаж)
    по counterparty_id (ИНН/идентификатор контрагента).
    """
    inn = (inn or "").strip()
    counterparty_id = (counterparty_id or "").strip()

    if not inn:
        return {"success": False, "error": {"message": "inn обязателен"}}
    # Если counterparty_id не задан — вернём все найденные строки книги продаж (раздел 9).

    today = datetime.now()
    if not date_to:
        date_to = today.strftime("%d.%m.%Y")
    if not date_from:
        date_from = (today - timedelta(days=120)).strftime("%d.%m.%Y")

    auth = sbis_auth_session_for_inn(
        inn,
        prewarm_proxies=True,
        proxy_want=max(2, int(proxy_prewarm_count)),
        proxy_warmup_budget_sec=max(8, int(auth_budget_sec)),
        auth_timeout_sec=max(8, int(auth_timeout_sec)),
        auth_budget_sec=max(12, int(auth_budget_sec)),
    )
    if not auth.get("success"):
        return auth

    session_id = (((auth.get("result") or {}).get("session_id")) or "").strip()
    if not session_id:
        return {"success": False, "error": {"message": "Не удалось получить session_id", "inn": inn}}

    list_filter = {
        "Тип": "ОтчетФНС",
        "Направление": "Исходящий",
        "ДатаС": date_from,
        "ДатаПо": date_to,
        "Навигация": {"РазмерСтраницы": str(int(max_docs))},
    }
    if (nds_subtype or "").strip():
        list_filter["Подтип"] = str(nds_subtype).strip()

    list_params = {"Фильтр": list_filter}

    try:
        data = sbis_rpc(
            inn=inn,
            session_id=session_id,
            method="СБИС.СписокДокументов",
            params=list_params,
            timeout=max(8, int(rpc_timeout_sec)),
            total_budget_sec=max(12, int(rpc_budget_sec)),
        )
    except Exception as e:
        msg = str(e)
        unknown_subtype = "неизвестный тип/подтип документа" in msg.lower()
        if unknown_subtype and "Подтип" in list_filter:
            # Фолбэк: у некоторых организаций/провайдеров подтип может не приниматься,
            # тогда запрашиваем без подтипа и фильтруем уже по данным архива.
            list_filter.pop("Подтип", None)
            try:
                data = sbis_rpc(
                    inn=inn,
                    session_id=session_id,
                    method="СБИС.СписокДокументов",
                    params={"Фильтр": list_filter},
                    timeout=max(8, int(rpc_timeout_sec)),
                    total_budget_sec=max(12, int(rpc_budget_sec)),
                )
            except Exception as e2:
                return {"success": False, "error": {"message": f"Ошибка СБИС.СписокДокументов: {e2}", "inn": inn}}
        else:
            return {"success": False, "error": {"message": f"Ошибка СБИС.СписокДокументов: {e}", "inn": inn}}

    if data.get("error"):
        return {"success": False, "error": {"message": f"СБИС error: {data['error']}", "inn": inn}}

    docs = (((data.get("result") or {}).get("Документ")) or [])
    if sbis_doc_id:
        docs = [d for d in docs if (d.get("Идентификатор") or "").strip() == (sbis_doc_id or "").strip()]

    matched_docs: list[dict] = []
    scanned_docs = 0

    for doc in docs:
        if scanned_docs >= max_docs:
            break
        scanned_docs += 1

        doc_id = (doc.get("Идентификатор") or "").strip()
        archive_url = (doc.get("СсылкаНаАрхив") or "").strip()
        if not archive_url:
            continue

        try:
            zip_bytes = _download_archive_zip(
                inn=inn,
                session_id=session_id,
                archive_url=archive_url,
                timeout=max(8, int(archive_timeout_sec)),
                total_budget_sec=max(12, int(archive_budget_sec)),
            )
            xml_files = _extract_xml_files_from_zip(zip_bytes)
        except Exception as e:
            matched_docs.append(
                {
                    "doc_id": doc_id,
                    "name": doc.get("Название"),
                    "archive_url": archive_url,
                    "ok": False,
                    "error": str(e),
                }
            )
            continue

        xml_matches: list[dict] = []
        for xml_name, xml_bytes in xml_files:
            filtered = _collect_sales_book_rows(
                xml_bytes,
                counterparty_id=counterparty_id,
            )
            if (filtered.get("total_rows") or 0) > 0:
                xml_matches.append(
                    {
                        "xml_name": xml_name,
                        "total_rows": filtered.get("total_rows"),
                        "rows": filtered.get("rows") or [],
                    }
                )

        if xml_matches:
            matched_docs.append(
                {
                    "doc_id": doc_id,
                    "name": doc.get("Название"),
                    "created_at": doc.get("ДатаВремяСоздания") or doc.get("Дата"),
                    "archive_url": archive_url,
                    "ok": True,
                    "xml_matches": xml_matches,
                }
            )

    return {
        "success": True,
        "result": {
            "inn": inn,
            "counterparty_id": counterparty_id,
            "mode": "by_counterparty" if counterparty_id else "all_sales_books",
            "endpoint": REPORTING_URL,
            "method": "СБИС.СписокДокументов",
            "period": {"from": date_from, "to": date_to},
            "nds_subtype": nds_subtype,
            "scanned_docs": scanned_docs,
            "timeouts": {
                "auth_timeout_sec": int(auth_timeout_sec),
                "auth_budget_sec": int(auth_budget_sec),
                "rpc_timeout_sec": int(rpc_timeout_sec),
                "rpc_budget_sec": int(rpc_budget_sec),
                "archive_timeout_sec": int(archive_timeout_sec),
                "archive_budget_sec": int(archive_budget_sec),
            },
            "proxy_prewarm_count": int(proxy_prewarm_count),
            "matched_docs_count": len([x for x in matched_docs if x.get("ok")]),
            "documents": matched_docs,
        },
    }