from datetime import date
from typing import List, Literal, Optional

from pydantic import BaseModel, constr


class MailLookupRequest(BaseModel):
    inn: constr(min_length=10, max_length=12, pattern=r"^\d{10,12}$")
    requested_date: date
    include_attachments: bool = False


class MailLookupResponse(BaseModel):
    inn: str
    requested_date: date
    status: Literal["FOUND", "PENDING", "NOT_FOUND", "ERROR"]
    email: Optional[str] = None
    attachments: Optional[List[dict]] = None
    job_id: Optional[str] = None
    message: Optional[str] = None
