"""Fortinet (FortiGate) device identification.

FortiGate's sysDescr is EMPTY, so it can't be parsed. Everything comes from
SNMP instead:

  * model    -> last arc of sysObjectID, looked up in fortinet_models.json
  * firmware -> fgSysVersion  (1.3.6.1.4.1.12356.101.4.1.1.0),
                e.g. "v6.0.16,build0505,221215 (GA)" -> "6.0.16"
  * serial   -> fnSysSerial   (1.3.6.1.4.1.12356.100.1.1.1.0)
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from typing import Optional

OID_FG_SYS_VERSION = "1.3.6.1.4.1.12356.101.4.1.1.0"
OID_FN_SYS_SERIAL = "1.3.6.1.4.1.12356.100.1.1.1.0"

_MODELS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "fortinet_models.json"
)

# Firmware looks like "v6.0.16,build0505,221215 (GA)" — grab the dotted version
# after the leading "v", before the first comma.
_FIRMWARE_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)?)")


@lru_cache(maxsize=1)
def _models() -> dict:
    """Load (and cache) the number->model-name map from fortinet_models.json."""
    with open(_MODELS_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _model_from_object_id(sys_object_id: Optional[str]) -> Optional[str]:
    if not sys_object_id:
        return None
    last_arc = sys_object_id.rstrip(".").split(".")[-1]
    return _models().get(last_arc)


def _parse_firmware(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    match = _FIRMWARE_RE.search(raw)
    return match.group(1) if match else None


async def identify(
    sys_descr: Optional[str],
    sys_object_id: Optional[str],
    snmp_client,
    ip: str,
) -> dict:
    """Return FortiGate-specific fields via extra SNMP GETs."""
    extra = await snmp_client.get_many(
        ip, [OID_FG_SYS_VERSION, OID_FN_SYS_SERIAL]
    )
    extra = extra or {}

    return {
        "model": _model_from_object_id(sys_object_id),
        "firmware": _parse_firmware(extra.get(OID_FG_SYS_VERSION)),
        "serial": extra.get(OID_FN_SYS_SERIAL),
    }
