"""The Wazuh server's own CVEs, from its syscollector package list matched
with OSV.dev. Wazuh never indexes agent 000 into the package and
vulnerability states, so without this the server is always unscored.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

log = logging.getLogger("vulnmapper.endpoints")


def _shape(value) -> str:
    """What a reply looks like (types and keys, never values), for a log line."""
    if isinstance(value, dict):
        return "{" + ", ".join(f"{k}: {type(v).__name__}" for k, v in value.items()) + "}"
    if isinstance(value, list):
        return f"list of {len(value)}" + (f", first {_shape(value[0])}" if value else "")
    return type(value).__name__


def ecosystem(os_items) -> tuple:
    """``(OSV ecosystem, None)`` from the server's /syscollector/000/os items,
    or ``(None, reason)``. Ubuntu LTS releases are named with ":LTS"
    ("Ubuntu:22.04:LTS"), as OSV lists them; interim ones without it."""
    item = os_items[0] if isinstance(os_items, list) and os_items else None
    os_info = item.get("os") if isinstance(item, dict) else None
    if not isinstance(os_info, dict):
        log.warning("Wazuh server OS: unexpected syscollector reply (%s)", _shape(os_items))
        return None, "its OS is not in the syscollector inventory"
    name = str(os_info.get("platform") or os_info.get("name") or "").lower()
    major, minor = str(os_info.get("major") or ""), str(os_info.get("minor") or "")
    if not major:
        m = re.match(r"(\d+)(?:\.(\d+))?", str(os_info.get("version") or ""))
        major, minor = (m.group(1), m.group(2) or "") if m else ("", "")
    if "ubuntu" in name and major.isdigit() and minor.isdigit():
        release = f"{major}.{int(minor):02d}"
        lts = int(major) % 2 == 0 and int(minor) == 4
        return f"Ubuntu:{release}" + (":LTS" if lts else ""), None
    if "debian" in name and major.isdigit():
        return f"Debian:{major}", None
    shown = " ".join(str(os_info.get(k) or "") for k in ("name", "version")).strip()
    return None, f"OSV matching is not set up for its OS ({shown or 'unknown'})"
