from __future__ import annotations

import os
from typing import Any, Callable


def _simulated_pkcs11_probe() -> dict[str, Any]:
    raw_mode = os.getenv("RST_PKCS11_FIPS_MODE", "false").strip().lower()
    return {
        "provider": "simulated-pkcs11",
        "module": os.getenv("RST_PKCS11_MODULE", "pkcs11-simulator.so"),
        "slot": os.getenv("RST_PKCS11_SLOT", "0"),
        "token": os.getenv("RST_PKCS11_TOKEN", "rst-hsm"),
        "fips_mode": raw_mode in {"1", "true", "yes", "on"},
    }


def check_hsm_fips_140_3_mode(
    *,
    probe: Callable[[], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    details = (probe or _simulated_pkcs11_probe)()
    fips_mode = bool(details.get("fips_mode"))
    return {
        "status": "pass" if fips_mode else "fail",
        "standard": "FIPS 140-3",
        "reason": (
            "HSM is operating in FIPS 140-3 mode"
            if fips_mode
            else "HSM is not operating in FIPS 140-3 mode"
        ),
        "details": details,
    }
