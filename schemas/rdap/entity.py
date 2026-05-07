"""
Pydantic schema for an RDAP Entity response.

Validates against RFC 9083 §5.1 and the gTLD RDAP Profile.
"""

from __future__ import annotations

from typing import Any, List, Optional
from pydantic import BaseModel, field_validator

from schemas.rdap.common import (
    RDAPConformance,
    RDAPEntity,
    RDAPEvent,
    RDAPLink,
    RDAPNotice,
    RDAPPublicID,
)


class RDAPEntityResponse(BaseModel):
    """
    Top-level RDAP Entity response object (RFC 9083 §5.1).

    Required by gTLD RDAP Profile:
    - objectClassName == "entity"
    - handle present
    - rdapConformance present at top level
    """

    objectClassName: str
    handle: Optional[str] = None
    vcardArray: Optional[List[Any]] = None
    roles: Optional[List[str]] = None
    publicIds: Optional[List[RDAPPublicID]] = None
    entities: Optional[List[RDAPEntity]] = None
    remarks: Optional[List[RDAPNotice]] = None
    links: Optional[List[RDAPLink]] = None
    events: Optional[List[RDAPEvent]] = None
    status: Optional[List[str]] = None
    port43: Optional[str] = None
    networks: Optional[List[Any]] = None
    autnums: Optional[List[Any]] = None
    notices: Optional[List[RDAPNotice]] = None
    rdapConformance: Optional[RDAPConformance] = None
    lang: Optional[str] = None

    model_config = {"extra": "allow"}

    @field_validator("objectClassName")
    @classmethod
    def must_be_entity(cls, v: str) -> str:
        if v != "entity":
            raise ValueError(f"objectClassName must be 'entity', got '{v}'")
        return v
