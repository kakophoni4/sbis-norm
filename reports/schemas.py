from datetime import date
from typing import List, Optional, Literal

from pydantic import BaseModel, Field, validator, constr

import base64
import hashlib
import re


class FileSchema(BaseModel):
    name: str = Field(
        ...,
        description="Имя файла, включая расширение (e.g., 'file1.xml')",
    )
    base64_string: str = Field(
        ...,
        description="Содержимое файла в кодировке base64",
    )
    checksum: str = Field(
        ...,
        description="Контрольная сумма файла (SHA-256)",
    )

    @validator('name')
    def validate_filename(cls, v: str) -> str:
        if not re.match(r'^[a-zA-Z0-9_.-]+\.(xml|pdf|XML|PDF)$', v):
            raise ValueError(
                'Invalid filename. Only xml/pdf and basic characters are allowed.'
            )
        return v

    @validator('base64_string')
    def validate_base64_and_size(cls, v: str) -> str:
        try:
            decoded_content = base64.b64decode(v, validate=True)
            if len(decoded_content) > 10 * 1024 * 1024:  # 10MB limit
                raise ValueError('File size exceeds 10MB limit')
        except (ValueError, TypeError):
            raise ValueError('Invalid base64 string')
        return v


class SubmitReportSchema(BaseModel):
    inn: str = Field(
        ...,
        min_length=10,
        max_length=12,
        pattern=r'^\d{10,12}$',
        description="ИНН организации",
    )
    report_type: str = Field(..., description="Код типа отчета, e.g., '1151001'")
    files: List[FileSchema] = Field(..., description="Список файлов для отправки")
    theme: Optional[str] = Field(None, description="Тема/примечание к отчету")
    tax_office_code: str = Field(..., description="Код налогового органа")
    period_code: str = Field(..., description="Код отчетного периода, e.g., '22'")
    year: str = Field(..., description="Отчетный год, e.g., '2025'")
    form_name: Optional[str] = Field(None, description="Наименование формы отчета")

    @validator('files')
    def validate_files_checksums(cls, v: List[FileSchema]) -> List[FileSchema]:
        for file_data in v:
            decoded_file = base64.b64decode(file_data.base64_string)
            computed_hash = hashlib.sha256(decoded_file).hexdigest()
            if computed_hash != file_data.checksum:
                raise ValueError(f"Checksum mismatch for file '{file_data.name}'")
        return v


class StatusResponseSchema(BaseModel):
    id: str
    status: str
    events: List[dict]


class MailLookupRequest(BaseModel):
    inn: constr(min_length=10, max_length=12, pattern=r'^\d{10,12}$')
    requested_date: date
    include_attachments: bool = False


class MailLookupResponse(BaseModel):
    inn: str
    requested_date: date
    status: Literal['FOUND', 'PENDING', 'NOT_FOUND', 'ERROR']
    email: Optional[str] = None
    attachments: Optional[List[dict]] = None  # если include_attachments=True
    job_id: Optional[str] = None              # если задача отправлена в Celery
    message: Optional[str] = None             # текст ошибки/пояснения
