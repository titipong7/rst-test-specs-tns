"""
Pydantic schema for an RDAP Nameserver response.

Validates against RFC 9083 §5.2 and the gTLD RDAP Profile.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, field_validator

from schemas.rdap.common import (
    RDAPConformance,
    RDAPEntity,
    RDAPEvent,
    RDAPLink,
    RDAPNotice,
)


class IPAddresses(BaseModel):
    v4: Optional[List[str]] = None
    v6: Optional[List[str]] = None

    model_config = {"extra": "allow"}


class RDAPNameserverResponse(BaseModel):
    """
    RDAP Nameserver response object (RFC 9083 §5.2).

    Required by gTLD RDAP Profile:
    - objectClassName == "nameserver"
    - ldhName present
    - rdapConformance present at top level
    """

    objectClassName: str
    handle: Optional[str] = None
    ldhName: Optional[str] = None
    unicodeName: Optional[str] = None
    ipAddresses: Optional[IPAddresses] = None
    entities: Optional[List[RDAPEntity]] = None
    status: Optional[List[str]] = None
    remarks: Optional[List[RDAPNotice]] = None
    links: Optional[List[RDAPLink]] = None
    port43: Optional[str] = None
    events: Optional[List[RDAPEvent]] = None
    notices: Optional[List[RDAPNotice]] = None
    rdapConformance: Optional[RDAPConformance] = None
    lang: Optional[str] = None

    model_config = {"extra": "allow"}

    @field_validator("objectClassName")
    @classmethod
    def must_be_nameserver(cls, v: str) -> str:
        if v != "nameserver":
            raise ValueError(f"objectClassName must be 'nameserver', got '{v}'")
        return v
