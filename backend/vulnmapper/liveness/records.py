"""The rules for one node's liveness record: what a reply, a miss or a
"gone" verdict does to it, and how a Wazuh agent row is read.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Optional

# Wazuh agent check-in (method "agent")
AGENT_MAX_AGE_S = 30            # a check-in older than this is a miss
AGENT_DOWN = {"disconnected", "pending", "never_connected"}
MANAGER_AGENT_ID = "000"        # reports a far-future lastKeepAlive
# Methods whose silence counts as a miss before any reply was ever seen. The
# scan found a host's MAC in its switch's table, so its absence there is
# evidence too.
PROVEN_FROM_START = {"agent", "mac-table"}


def _valid_ip(ip) -> bool:
    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return True


def _parse_time(text) -> Optional[datetime]:
    if not isinstance(text, str):
        return None
    try:
        t = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _agent_verdict(row: dict, now: datetime, max_age: float) -> tuple:
    """``(replied, down)`` for one Manager API agent row."""
    status = str(row.get("status") or "").lower()
    if status in AGENT_DOWN:
        return False, True
    if status != "active":
        return False, False
    if str(row.get("id")) == MANAGER_AGENT_ID:
        return True, False
    seen = _parse_time(row.get("lastKeepAlive"))
    return seen is not None and (now - seen).total_seconds() <= max_age, False


def _carry(old: dict, now: str) -> dict:
    """A fresh record carrying the fields that survive across passes."""
    rec = {
        "state": old.get("state") or "unknown",
        "method": old.get("method"),
        "misses": old.get("misses") if isinstance(old.get("misses"), int) else 0,
        "last_seen": old.get("last_seen"),
        "last_checked": now,
        "proven_methods": list(old.get("proven_methods") or []),   # a copy, never shared
    }
    if isinstance(old.get("port_down"), dict):
        rec["port_down"] = dict(old["port_down"])
    if isinstance(old.get("agent"), dict):
        rec["agent"] = dict(old["agent"])       # the last known check-in
    return rec


def _apply_probe(rec: dict, method: str, replied: bool, threshold: int, now: str,
                 down: bool = False) -> None:
    rec["method"] = method
    if replied:
        rec.update(state="active", misses=0, last_seen=now)
        if method not in rec["proven_methods"]:
            rec["proven_methods"].append(method)
    elif down:                  # the source says outright that it is gone
        rec["misses"] += 1
        rec["state"] = "inactive"
    elif method in rec["proven_methods"] or method in PROVEN_FROM_START:
        rec["misses"] += 1
        if rec["misses"] >= threshold:
            rec["state"] = "inactive"
    # silence on a never-proven method: nothing changes
