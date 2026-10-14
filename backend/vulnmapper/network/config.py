"""How a crawl is configured: its limits and the SNMP credentials to try.

Credentials come from the command line and the environment, never from a
file, and a community string is never written to a log.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from typing import Optional

from .model import Credential

# Worker coroutines pulling from the crawl queue: at most this many devices
# are polled at once. 32 is comfortable on real hardware without overrunning
# the OS's UDP receive buffer.
DEFAULT_CONCURRENCY = 32

# Seconds per SNMP request; tight, so a dead address frees its worker quickly.
DEFAULT_TIMEOUT = 1.0

# SNMP runs over UDP: one retry absorbs a dropped packet without turning every
# silent address into a multi-second stall.
DEFAULT_RETRIES = 1

# Safety cap on devices, so a misconfigured network cannot run the crawl away.
DEFAULT_MAX_NODES = 5000

DEFAULT_PORT = 161

# The one community typed into the dashboard's scan form, taken exactly as typed
# (spaces, commas and quotes are part of it) and tried first.
ENV_FORM_COMMUNITY = "VULNMAPPER_SNMP_COMMUNITY"
ENV_COMMUNITIES = "SNMP_COMMUNITIES"   # comma/space separated list
ENV_COMMUNITY = "SNMP_COMMUNITY"       # single string
ENV_V3_USER = "SNMP_V3_USER"
ENV_V3_AUTH_PROTO = "SNMP_V3_AUTH_PROTO"
ENV_V3_AUTH_KEY = "SNMP_V3_AUTH_KEY"
ENV_V3_PRIV_PROTO = "SNMP_V3_PRIV_PROTO"
ENV_V3_PRIV_KEY = "SNMP_V3_PRIV_KEY"


@dataclass
class Config:
    credentials: list[Credential]
    seeds: list[str]
    concurrency: int = DEFAULT_CONCURRENCY
    timeout: float = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES
    max_nodes: int = DEFAULT_MAX_NODES
    port: int = DEFAULT_PORT
    pollable_only: bool = False
    output_path: Optional[str] = None
    # Read the configuration-check tables while polling and, only if the owner
    # asked for it, try the factory community names.
    checklist: bool = False
    check_default_communities: bool = False
    # Connect to TCP 23 and 80 on devices that do not list their listeners.
    check_management_ports: bool = False

    @property
    def queue_maxsize(self) -> int:
        """The crawl queue's bound.

        The queue holds only small (ip, chassis id) tuples, and the max-nodes
        cap already bounds how many can exist. Sizing it to the cap keeps it
        from becoming a second limit, and from deadlocking: the workers that
        fill the queue are the ones that drain it.
        """
        return self.max_nodes


def _split(raw: Optional[str]) -> list[str]:
    """"a,b,c" or "a b c" (shlex, so quoted names work), blanks dropped."""
    if not raw:
        return []
    try:
        return [tok for chunk in raw.split(",") for tok in shlex.split(chunk) if tok]
    except ValueError:
        # never echo the value: it is a secret
        raise SystemExit(f"vulnmapper: {ENV_COMMUNITIES} could not be parsed (unbalanced quote)") from None


def load_credentials(cli_communities: Optional[list[str]]) -> list[Credential]:
    """The credentials to try, in order: ``--community`` values, then
    ``$VULNMAPPER_SNMP_COMMUNITY`` (unsplit), ``$SNMP_COMMUNITIES`` and
    ``$SNMP_COMMUNITY`` (one string, trimmed), then one v3 credential if the
    ``$SNMP_V3_*`` variables are set. Duplicates are dropped."""
    seen: set[tuple] = set()
    creds: list[Credential] = []

    def add_community(community: str) -> None:
        key = ("v2c", community)
        if community and key not in seen:
            seen.add(key)
            creds.append(Credential(version="v2c", index=len(creds) + 1, community=community))

    for community in cli_communities or []:
        add_community(community)
    add_community(os.environ.get(ENV_FORM_COMMUNITY) or "")
    for community in _split(os.environ.get(ENV_COMMUNITIES)):
        add_community(community)
    add_community((os.environ.get(ENV_COMMUNITY) or "").strip())

    v3_user = os.environ.get(ENV_V3_USER)
    if v3_user:
        add_v3_credential(creds, user=v3_user,
                          auth_protocol=os.environ.get(ENV_V3_AUTH_PROTO),
                          auth_key=os.environ.get(ENV_V3_AUTH_KEY),
                          priv_protocol=os.environ.get(ENV_V3_PRIV_PROTO),
                          priv_key=os.environ.get(ENV_V3_PRIV_KEY))
    return creds


def add_v3_credential(creds: list[Credential], *, user: str, auth_protocol: Optional[str],
                      auth_key: Optional[str], priv_protocol: Optional[str],
                      priv_key: Optional[str]) -> None:
    creds.append(Credential(version="v3", index=len(creds) + 1, user=user,
                            auth_protocol=auth_protocol, auth_key=auth_key,
                            priv_protocol=priv_protocol, priv_key=priv_key))
