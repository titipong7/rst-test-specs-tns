"""
Pydantic schema for an RDAP Help response.

Validates against RFC 9083 §7.4 and the gTLD RDAP Profile.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel

from schemas.rdap.common import (
    RDAPConformance,
    RDAPLink,
    RDAPNotice,
)


class RDAPHelpResponse(BaseModel):
    """
    RDAP Help (/help) response object (RFC 9083 §7.4).

    Required by gTLD RDAP Profile:
    - rdapConformance present
    - At least one notice
    """

    rdapConformance: RDAPConformance
    notices: Optional[List[RDAPNotice]] = None
    links: Optional[List[RDAPLink]] = None
    lang: Optional[str] = None

    model_config = {"extra": "allow"}

    def has_notices(self) -> bool:
        return bool(self.notices)
