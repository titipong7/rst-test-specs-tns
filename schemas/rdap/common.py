"""
Common Pydantic building-blocks shared across all RDAP response schemas.

These types are derived from RFC 9083 and the gTLD RDAP Profile.
"""

from __future__ import annotations

from typing import Any, List, Optional
from pydantic import BaseModel, AnyHttpUrl, field_validator


class RDAPLink(BaseModel):
    """RFC 9083 §4.2 – Links."""

    value: Optional[str] = None
    rel: Optional[str] = None
    href: str
    type: Optional[str] = None
    hreflang: Optional[List[str]] = None
    title: Optional[str] = None
    media: Optional[str] = None

    model_config = {"extra": "allow"}


class RDAPNotice(BaseModel):
    """RFC 9083 §4.3 – Notices and Remarks."""

    title: Optional[str] = None
    description: List[str]
    links: Optional[List[RDAPLink]] = None
    type: Optional[str] = None

    model_config = {"extra": "allow"}


class RDAPEvent(BaseModel):
    """RFC 9083 §4.5 – Events."""

    eventAction: str
    eventDate: str
    eventActor: Optional[str] = None
    links: Optional[List[RDAPLink]] = None

    model_config = {"extra": "allow"}


class RDAPPublicID(BaseModel):
    """RFC 9083 §4.8 – Public IDs."""

    type: str
    identifier: str

    model_config = {"extra": "allow"}


class RDAPEntity(BaseModel):
    """RFC 9083 §5.1 – Entity."""

    objectClassName: str = "entity"
    handle: Optional[str] = None
    vcardArray: Optional[List[Any]] = None
    roles: Optional[List[str]] = None
    publicIds: Optional[List[RDAPPublicID]] = None
    entities: Optional[List["RDAPEntity"]] = None
    remarks: Optional[List[RDAPNotice]] = None
    links: Optional[List[RDAPLink]] = None
    events: Optional[List[RDAPEvent]] = None
    status: Optional[List[str]] = None
    port43: Optional[str] = None
    networks: Optional[List[Any]] = None
    autnums: Optional[List[Any]] = None

    model_config = {"extra": "allow"}


RDAPEntity.model_rebuild()


# RFC 9083 §4.1 – rdapConformance
RDAPConformance = List[str]


class RDAPError(BaseModel):
    """RFC 9083 §6 – Error Response."""

    errorCode: int
    title: Optional[str] = None
    description: Optional[List[str]] = None
    notices: Optional[List[RDAPNotice]] = None
    lang: Optional[str] = None
    rdapConformance: Optional[RDAPConformance] = None

    model_config = {"extra": "allow"}

    @field_validator("errorCode")
    @classmethod
    def must_be_http_error(cls, v: int) -> int:
        if v < 400 or v > 599:
            raise ValueError(f"RDAP error code must be 4xx or 5xx, got {v}")
        return v
