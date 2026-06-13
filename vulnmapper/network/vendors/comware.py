"""HP / H3C Comware device identification (e.g. the HP 1920 switch family).

Comware's sysDescr carries the platform and firmware in plain text::

    1920-48G Switch Software Version 5.20.99, Release 1107
    Copyright(c)2010-2015 Hewlett-Packard Development Company, L.P.

but, unlike Cisco, there is NO "Comware" (or "H3C"/"HP") token to dispatch on —
the vendor string is literally "Hewlett-Packard Development Company". So vendor
routing keys on the sysObjectID enterprise arc (25506, the H3C/HP/3Com arc) via
:data:`vulnmapper.network.vendors.VENDOR_BY_ENTERPRISE`, never on a sysDescr
substring. See :func:`matches`.

  * model    -> sysObjectID looked up in comware_models.json
  * firmware -> sysDescr "Version <x.y.z>, Release <nnnn>" -> "x.y.z Release nnnn"
  * serial   -> left null (like Cisco); the graph doesn't need it and a reliable
                serial would cost an extra entity-MIB walk.

Note on the FDB: Comware returns dot1qTpFdbPort sorted by MAC, which the net-snmp
CLI rejects as "OID not increasing". This pipeline's walk (snmp_client.py) steps
GETNEXT-style from the last-returned OID, so it retrieves the full table without
any ``ignoreNonIncreasingOid`` workaround — verified live. There is therefore no
Comware-specific FDB branch: the existing default-context dot1q path handles it.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from typing import Optional

# The H3C/HP/3Com enterprise arc. Vendor routing keys on this prefix; the HP 1920
# sysDescr contains no vendor/OS token to match, so sysObjectID is the only
# reliable discriminator.
ENTERPRISE_PREFIX = "1.3.6.1.4.1.25506"

_MODELS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "comware_models.json"
)

# "... Software Version 5.20.99, Release 1107" -> ("5.20.99", "1107").
# Deliberately vendor-token-agnostic: it keys off "Version"/"Release", never the
# "HP"/"Hewlett-Packard"/"Comware" string.
_VERSION_RE = re.compile(r"Version (\d+\.\d+\.\d+), Release (\d+)")


def matches(sys_object_id: Optional[str]) -> bool:
    """Whether a sysObjectID belongs to the Comware (H3C/HP) enterprise arc."""
    return bool(sys_object_id) and sys_object_id.startswith(ENTERPRISE_PREFIX)


@lru_cache(maxsize=1)
def _models() -> dict:
    """Load (and cache) the sysObjectID -> model-name map from comware_models.json."""
    with open(_MODELS_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _model_from_object_id(sys_object_id: Optional[str]) -> Optional[str]:
    # Keyed on the FULL sysObjectID, not a last-arc, because the Comware product
    # tree is deep (25506.11.1.<model>) and a bare last arc collides across
    # sub-branches.
    if not sys_object_id:
        return None
    return _models().get(sys_object_id.rstrip("."))


def parse_version(sys_descr: Optional[str]) -> dict:
    """Parse a Comware sysDescr into ``{'version', 'release'}`` (None if absent)."""
    match = _VERSION_RE.search(sys_descr or "")
    if not match:
        return {"version": None, "release": None}
    return {"version": match.group(1), "release": match.group(2)}


def _firmware(sys_descr: Optional[str]) -> Optional[str]:
    parsed = parse_version(sys_descr)
    if parsed["version"] is None:
        return None
    if parsed["release"]:
        return f"{parsed['version']} Release {parsed['release']}"
    return parsed["version"]


async def identify(
    sys_descr: Optional[str],
    sys_object_id: Optional[str],
    snmp_client,
    ip: str,
) -> dict:
    """Return Comware-specific fields. No extra SNMP round-trips are needed —
    model and firmware come from the sysObjectID + sysDescr already fetched by
    :mod:`vulnmapper.network.sysinfo`. ``snmp_client``/``ip`` are accepted for
    interface symmetry with the other vendor plug-ins.
    """
    return {
        "model": _model_from_object_id(sys_object_id),
        "firmware": _firmware(sys_descr),
        "serial": None,
    }
