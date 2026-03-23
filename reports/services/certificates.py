# reports/services/certificates.py
"""
Service layer for managing CryptoPro certificate containers.

Responsibilities:
* Run `certmgr -list` and parse command output.
* Extract INN values from certificate subjects.
* Create or update `Certificate` records.
* Write corresponding entries to `CertificateAuditLog`.
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass
from typing import Iterable, List, Optional

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from ..models import Certificate, CertificateAuditLog

logger = logging.getLogger(__name__)

DEFAULT_CERTMGR_PATH = "/opt/cprocsp/bin/amd64/certmgr"

SUBJECT_INN_PATTERN = re.compile(r"(?:ИНН|INN)\s*=\s*(\d{10,12})", re.IGNORECASE | re.UNICODE)
THUMBPRINT_LABELS = (
    "SHA1 Thumbprint",
    "SHA1 fingerprint",
    "Thumbprint",
)


class CertificateServiceError(Exception):
    """Base exception for certificate service errors."""


class CertmgrNotFoundError(CertificateServiceError):
    """Raised when certmgr executable is missing."""


class CertmgrExecutionError(CertificateServiceError):
    """Raised when certmgr command finishes with non-zero exit status."""


class CertmgrTimeoutError(CertificateServiceError):
    """Raised when certmgr command exceeds the given timeout."""


@dataclass(slots=True)
class LocalContainerInfo:
    """Represents a single certificate container discovered locally (имя как в csptest -enum_cont -fqcn)."""
    csptest_name: str
    subject: str
    thumbprint: Optional[str] = None
    serial: Optional[str] = None

    @property
    def inn(self) -> Optional[str]:
        """Extract INN (taxpayer ID) from the certificate subject string."""
        match = SUBJECT_INN_PATTERN.search(self.subject)
        return match.group(1) if match else None


def run_certmgr_list(
    certmgr_path: Optional[str] = None,
    *,
    timeout: Optional[int] = None,
) -> str:
    """
    Execute `certmgr -list` and return stdout.

    Raises:
        CertmgrNotFoundError
        CertmgrExecutionError
        CertmgrTimeoutError
    """
    path = certmgr_path or getattr(settings, "CERTMGR_PATH", DEFAULT_CERTMGR_PATH)
    command = [path, "-list"]

    logger.debug("Running certmgr list command: %s", " ".join(command))

    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        logger.error("certmgr executable not found at %s", path)
        raise CertmgrNotFoundError(f"certmgr not found at {path}") from exc
    except subprocess.TimeoutExpired as exc:
        logger.error("certmgr command timed out after %s seconds", timeout)
        raise CertmgrTimeoutError("certmgr command timed out") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        logger.error("certmgr command failed: %s", stderr)
        raise CertmgrExecutionError(stderr or "certmgr command failed") from exc

    stdout = result.stdout or ""
    logger.debug("certmgr output received (%d bytes)", len(stdout))
    return stdout


def _split_container_blocks(output: str) -> Iterable[str]:
    """
    Split certmgr output into individual container blocks.

    A block starts with a line `Container name:` and continues until the next such line.
    """
    current: List[str] = []
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if line.strip().startswith("Container name:"):
            if current:
                yield "\n".join(current)
                current = []
        if line:
            current.append(line)
    if current:
        yield "\n".join(current)


def _parse_container_block(block: str) -> Optional[LocalContainerInfo]:
    """
    Parse a single container block into LocalContainerInfo.

    Returns:
        LocalContainerInfo if minimal data is available, otherwise None.
    """
    data: dict[str, str] = {}
    current_field: Optional[str] = None

    for raw_line in block.splitlines():
        line = raw_line.strip()
        if line.startswith("Container name:"):
            data["csptest_name"] = line.split(":", 1)[1].strip()
            current_field = "csptest_name"
        elif line.startswith("Subject:"):
            data["subject"] = line.split(":", 1)[1].strip()
            current_field = "subject"
        elif line.startswith("Serial:"):
            data["serial"] = line.split(":", 1)[1].strip()
            current_field = "serial"
        elif any(line.startswith(label + ":") for label in THUMBPRINT_LABELS):
            label = next(label for label in THUMBPRINT_LABELS if line.startswith(label + ":"))
            data["thumbprint"] = line.split(":", 1)[1].strip()
            current_field = "thumbprint"
        else:
            if current_field == "subject" and line:
                data["subject"] = f"{data['subject']} {line}".strip()

    if "csptest_name" not in data or "subject" not in data:
        logger.debug("Skipping block due to missing data:\n%s", block)
        return None

    return LocalContainerInfo(
        csptest_name=data["csptest_name"],
        subject=data["subject"],
        thumbprint=data.get("thumbprint"),
        serial=data.get("serial"),
    )


def parse_certmgr_output(output: str) -> List[LocalContainerInfo]:
    """Parse certmgr output into a list of LocalContainerInfo instances."""
    containers: List[LocalContainerInfo] = []
    for block in _split_container_blocks(output):
        info = _parse_container_block(block)
        if info:
            containers.append(info)

    logger.info("Parsed %d certificate container(s) from certmgr output", len(containers))
    return containers


def _certificate_has_field(field_name: str) -> bool:
    """Check if Certificate model declares a field with the given name."""
    return any(field.name == field_name for field in Certificate._meta.fields)


def register_local_certificate(info: LocalContainerInfo) -> Optional[Certificate]:
    """
    Create or update a Certificate record for the given container.

    Returns:
        Certificate instance when registration succeeds, otherwise None
        (e.g., when INN cannot be extracted).
    """
    inn = info.inn
    if not inn:
        logger.warning("Unable to extract INN from subject: %s", info.subject)
        CertificateAuditLog.objects.create(
            inn="",
            cert=None,
            action="REGISTER_LOCAL_CERT",
            status="ERROR",
            message=f"Cannot extract INN from subject: {info.subject}",
        )
        return None

    now = timezone.now()
    defaults: dict[str, object] = {
        "inn": inn,
        "thumbprint": info.thumbprint,
        "source": "LOCAL",
        "is_active": True,
    }
    if _certificate_has_field("last_used_at"):
        defaults["last_used_at"] = now

    with transaction.atomic():
        cert, created = Certificate.objects.get_or_create(
            csptest_name=info.csptest_name,
            defaults=defaults,
        )

        updates: dict[str, object] = {}
        if created:
            logger.info("Created certificate record for container %s", info.csptest_name)
        else:
            if cert.inn != inn:
                updates["inn"] = inn
            if info.thumbprint and cert.thumbprint != info.thumbprint:
                updates["thumbprint"] = info.thumbprint
            if getattr(cert, "source", None) != "LOCAL":
                updates["source"] = "LOCAL"
            if getattr(cert, "is_active", True) is False:
                updates["is_active"] = True

        if _certificate_has_field("last_used_at"):
            updates["last_used_at"] = now

        if updates:
            for field, value in updates.items():
                setattr(cert, field, value)
            cert.save(update_fields=list(updates.keys()))
            logger.debug(
                "Updated certificate %s with fields: %s",
                cert.pk,
                ", ".join(updates.keys()),
            )

        CertificateAuditLog.objects.create(
            inn=inn,
            cert=cert,
            action="REGISTER_LOCAL_CERT",
            status="SUCCESS",
            message=(
                f"{'created' if created else 'updated'}; "
                f"subject={info.subject}; thumbprint={info.thumbprint}"
            ),
        )

    return cert


def refresh_local_certificates(
    *,
    certmgr_path: Optional[str] = None,
    timeout: Optional[int] = None,
) -> List[LocalContainerInfo]:
    """
    Run certmgr, parse certificates, and register/update them in the database.

    Returns:
        List of LocalContainerInfo objects discovered.
    """
    CertificateAuditLog.objects.create(
        inn="*",
        cert=None,
        action="CHECK_LOCAL",
        status="SUCCESS",
        message="Запуск сканирования локальных контейнеров",
    )

    try:
        output = run_certmgr_list(certmgr_path=certmgr_path, timeout=timeout)
    except CertificateServiceError as exc:
        CertificateAuditLog.objects.create(
            inn="*",
            cert=None,
            action="CHECK_LOCAL",
            status="ERROR",
            message=str(exc),
        )
        raise

    infos = parse_certmgr_output(output)

    for info in infos:
        try:
            register_local_certificate(info)
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.exception("Failed to register certificate %s", info.csptest_name)
            CertificateAuditLog.objects.create(
                inn=info.inn or "UNKNOWN",
                cert=None,
                action="REGISTER_LOCAL_CERT",
                status="ERROR",
                message=str(exc),
            )

    return infos


def ensure_certificate_record(inn: str) -> Optional[Certificate]:
    """
    Ensure an active certificate exists for the provided INN.

    If missing, triggers a refresh and searches again.

    Returns:
        Certificate instance if found, otherwise None.
    """
    cert = Certificate.objects.filter(inn=inn, is_active=True).first()
    if cert:
        logger.debug("Certificate for INN %s already present (id=%s)", inn, cert.pk)
        return cert

    logger.info("Certificate for INN %s not found; running local refresh", inn)
    refresh_local_certificates()

    cert = Certificate.objects.filter(inn=inn, is_active=True).first()
    if cert:
        CertificateAuditLog.objects.create(
            inn=inn,
            cert=cert,
            action="ENSURE_CERTIFICATE",
            status="SUCCESS",
            message=f"Найден контейнер {cert.csptest_name}",
        )
        return cert

    CertificateAuditLog.objects.create(
        inn=inn,
        cert=None,
        action="ENSURE_CERTIFICATE",
        status="ERROR",
        message="Сертификат отсутствует",
    )
    logger.warning("Certificate for INN %s not found after refresh", inn)
    return None


__all__ = [
    "LocalContainerInfo",
    "CertificateServiceError",
    "CertmgrNotFoundError",
    "CertmgrExecutionError",
    "CertmgrTimeoutError",
    "run_certmgr_list",
    "parse_certmgr_output",
    "register_local_certificate",
    "refresh_local_certificates",
    "ensure_certificate_record",
]
