"""
Pydantic schema for an RDAP Domain response.

Validates against RFC 9083 §5.3 and the gTLD RDAP Profile (February-2024).
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


class RDAPNameserverInDomain(BaseModel):
    """Embedded nameserver object inside a domain response."""

    objectClassName: str = "nameserver"
    handle: Optional[str] = None
    ldhName: Optional[str] = None
    unicodeName: Optional[str] = None
    links: Optional[List[RDAPLink]] = None
    status: Optional[List[str]] = None
    remarks: Optional[List[RDAPNotice]] = None
    events: Optional[List[RDAPEvent]] = None

    model_config = {"extra": "allow"}


class SecureDNS(BaseModel):
    """RDAP Secure DNS block (RFC 9083 §5.3)."""

    zoneSigned: Optional[bool] = None
    delegationSigned: Optional[bool] = None
    maxSigLife: Optional[int] = None
    dsData: Optional[List[Any]] = None
    keyData: Optional[List[Any]] = None

    model_config = {"extra": "allow"}


class RDAPDomainResponse(BaseModel):
    """
    RDAP Domain response object.

    Required by gTLD RDAP Profile:
    - objectClassName == "domain"
    - ldhName (ASCII) or unicodeName
    - rdapConformance present at top level
    - At least one event (registration date)
    - At least one entity with role "registrar"
    """

    objectClassName: str
    handle: Optional[str] = None
    ldhName: Optional[str] = None
    unicodeName: Optional[str] = None
    variants: Optional[List[Any]] = None
    nameservers: Optional[List[RDAPNameserverInDomain]] = None
    secureDNS: Optional[SecureDNS] = None
    entities: Optional[List[RDAPEntity]] = None
    status: Optional[List[str]] = None
    publicIds: Optional[List[RDAPPublicID]] = None
    remarks: Optional[List[RDAPNotice]] = None
    links: Optional[List[RDAPLink]] = None
    port43: Optional[str] = None
    events: Optional[List[RDAPEvent]] = None
    network: Optional[Any] = None
    notices: Optional[List[RDAPNotice]] = None
    rdapConformance: Optional[RDAPConformance] = None
    lang: Optional[str] = None

    model_config = {"extra": "allow"}

    @field_validator("objectClassName")
    @classmethod
    def must_be_domain(cls, v: str) -> str:
        if v != "domain":
            raise ValueError(f"objectClassName must be 'domain', got '{v}'")
        return v

    def has_registrar_entity(self) -> bool:
        """Return True if at least one entity carries the 'registrar' role."""
        for entity in self.entities or []:
            if entity.roles and "registrar" in entity.roles:
                return True
        return False

    def has_registration_event(self) -> bool:
        """Return True if a 'registration' event is present."""
        for event in self.events or []:
            if event.eventAction == "registration":
                return True
        return False
