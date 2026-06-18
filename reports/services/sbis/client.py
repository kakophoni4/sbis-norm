import base64
import hashlib
import io
import json
import logging
import os
import random
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import requests
from django.conf import settings
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, ProxyError, SSLError, Timeout

from reports.models import Certificate
from reports.nodemaven_sdk.nodemaven import NodeMavenClient

from .constants import (
    AUTH_URL,
    LOG_DIR,
    NODEMAVEN_CITY,
    NODEMAVEN_COUNTRY,
    REPORTING_URL,
    CertInvalidNoRetryError,
    _RETRYABLE_HTTP_STATUSES,
    _GOOD_PROXY_TTL_SECONDS,
    _PROXY_TTL_SECONDS,
    logger,
)

# Mutable state (import * не подтягивает имена с _)
_PROXY_CACHE: dict[tuple[str, str], tuple[float, dict]] = {}
_NODEMAVEN_CLIENT: NodeMavenClient | None = None
_NODEMAVEN_CLIENT_KEY: str | None = None
_GOOD_PROXY_POOL: dict[str, tuple[float, list[str]]] = {}

_thread_http = threading.local()

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
        or "не зарегистрирован" in t
    )

def _nodemaven_client() -> NodeMavenClient:
    global _NODEMAVEN_CLIENT, _NODEMAVEN_CLIENT_KEY

    api_key = (getattr(settings, "NODEMAVEN_API_KEY", None) or os.getenv("NODEMAVEN_API_KEY") or "").strip()
    if not api_key:
        raise RuntimeError("NODEMAVEN_API_KEY не задан")

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
    max_tries = 80
    while time.time() < deadline and len(good) < want and tries < max_tries:
        tries += 1
        sticky = uuid.uuid4().hex[:8]
        got_proxy_this_round = False

        for city in city_modes:
            if time.time() >= deadline or len(good) >= want:
                break

            try:
                p = _nodemaven_proxies(inn=inn, sticky_key=sticky, city=city)
                base = (p.get("http") or "").strip()
                if not base:
                    continue
                got_proxy_this_round = True
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

        if not got_proxy_this_round:
            time.sleep(0.3)

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
