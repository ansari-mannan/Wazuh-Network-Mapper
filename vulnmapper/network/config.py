"""All tunables in one place, plus credential loading from flags + environment.

Nothing else in the package should hard-code a timeout, a concurrency level, or
read a credential out of ``os.environ`` directly — it all funnels through here.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from typing import Optional

from .models import Credential

# ---- Defaults (override via CLI flags) ------------------------------------

# Worker coroutines pulling from the crawl queue. This is the real bound on
# in-flight work: at most this many devices are being polled at once, so the
# heavy state (SNMP requests, MIB decoding) is capped regardless of network
# size. 32 polls real infrastructure comfortably without overrunning the OS
# UDP receive buffer.
DEFAULT_CONCURRENCY = 32

# Per-request timeout (seconds). Kept tight so an unreachable device frees its
# worker in ~one timeout instead of being held for many seconds.
DEFAULT_TIMEOUT = 1.0

# SNMP retries per request. SNMP is UDP, so 1 retry absorbs a single dropped
# packet without turning every probe into a multi-second stall.
DEFAULT_RETRIES = 1

# Safety cap on total nodes. A misconfigured or hostile environment cannot push
# the crawl past this many devices.
DEFAULT_MAX_NODES = 5000

DEFAULT_PORT = 161

# Environment variable names. Communities are loaded from the environment to
# match how the project's other collectors take credentials from the env rather
# than only from the command line.
ENV_COMMUNITIES = "SNMP_COMMUNITIES"   # comma/space separated list
ENV_COMMUNITY = "SNMP_COMMUNITY"       # single string
ENV_V3_USER = "SNMP_V3_USER"
ENV_V3_AUTH_PROTO = "SNMP_V3_AUTH_PROTO"
ENV_V3_AUTH_KEY = "SNMP_V3_AUTH_KEY"
ENV_V3_PRIV_PROTO = "SNMP_V3_PRIV_PROTO"
ENV_V3_PRIV_KEY = "SNMP_V3_PRIV_KEY"

# Baked-in lab community (by request) so the crawl runs with no --community / env.
# CLI flags and env vars are still tried first; this is only the fallback when
# nothing else is supplied. Not for production.
DEFAULT_COMMUNITY = "cyfor123"


@dataclass
class Config:
    """Resolved run configuration handed to the crawler."""

    credentials: list[Credential]
    seeds: list[str]
    concurrency: int = DEFAULT_CONCURRENCY
    timeout: float = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES
    max_nodes: int = DEFAULT_MAX_NODES
    port: int = DEFAULT_PORT
    pollable_only: bool = False
    output_path: Optional[str] = None

    @property
    def queue_maxsize(self) -> int:
        """Backpressure bound for the crawl queue.

        The queue only ever holds lightweight ``(ip, chassis_id)`` next-hop
        tuples, and dedup on chassis ID plus the ``max_nodes`` cap bound how
        many can ever exist. Sizing it to ``max_nodes`` keeps the queue from
        being a second, conflicting limit (and avoids a producer/consumer
        deadlock, since the workers that fill the queue also drain it) while the
        real in-flight memory bound stays the worker pool.
        """
        return self.max_nodes


def _split(raw: Optional[str]) -> list[str]:
    """Split a comma/whitespace separated credential list, dropping blanks."""
    if not raw:
        return []
    # Allow either "a,b,c" or "a b c"; shlex handles quoted strings too.
    return [tok for chunk in raw.split(",") for tok in shlex.split(chunk) if tok]


def load_credentials(cli_communities: Optional[list[str]]) -> list[Credential]:
    """Assemble the credential trial set from CLI flags and the environment.

    Order: CLI ``--community`` values first (operator's explicit intent), then
    any from ``$SNMP_COMMUNITIES`` / ``$SNMP_COMMUNITY``, then a single v3
    credential if the ``$SNMP_V3_*`` variables are set. Duplicates collapse.
    """
    seen: set[tuple] = set()
    creds: list[Credential] = []

    def _add_community(community: str) -> None:
        key = ("v2c", community)
        if community and key not in seen:
            seen.add(key)
            creds.append(Credential(version="v2c", index=len(creds) + 1, community=community))

    for community in cli_communities or []:
        _add_community(community)
    for community in _split(os.environ.get(ENV_COMMUNITIES)):
        _add_community(community)
    for community in _split(os.environ.get(ENV_COMMUNITY)):
        _add_community(community)

    v3_user = os.environ.get(ENV_V3_USER)
    if v3_user:
        creds.append(
            Credential(
                version="v3",
                index=len(creds) + 1,
                user=v3_user,
                auth_protocol=os.environ.get(ENV_V3_AUTH_PROTO),
                auth_key=os.environ.get(ENV_V3_AUTH_KEY),
                priv_protocol=os.environ.get(ENV_V3_PRIV_PROTO),
                priv_key=os.environ.get(ENV_V3_PRIV_KEY),
            )
        )

    # Nothing supplied anywhere: fall back to the baked-in lab community so a
    # bare run still crawls (by request — see DEFAULT_COMMUNITY).
    if not creds:
        _add_community(DEFAULT_COMMUNITY)

    return creds


def add_v3_credential(
    creds: list[Credential],
    *,
    user: str,
    auth_protocol: Optional[str],
    auth_key: Optional[str],
    priv_protocol: Optional[str],
    priv_key: Optional[str],
) -> None:
    """Append a v3 credential supplied via CLI flags."""
    creds.append(
        Credential(
            version="v3",
            index=len(creds) + 1,
            user=user,
            auth_protocol=auth_protocol,
            auth_key=auth_key,
            priv_protocol=priv_protocol,
            priv_key=priv_key,
        )
    )
