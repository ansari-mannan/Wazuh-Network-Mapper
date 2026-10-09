"""Hosts without a Wazuh agent: label them, and learn what they probably are.

A host is an endpoint-kind node. One with an ``agent_id`` is managed (active
or disconnected alike; the Wazuh server is agent 000); one without came from
a switch's forwarding table, an LLDP or CDP announcement, or an access
point's client list, and is unmanaged: nothing reports its software, so its
vulnerabilities are not known. Network devices are not hosts.

Passive clues, from data already in the graph (:func:`label`):

  mac_type    "global" (the first three bytes name a manufacturer in IEEE's
              registry) or "local" (locally administered: randomised or
              virtual, with no manufacturer)
  mac_vendor  the registry's organisation for a global MAC (None if absent)

risk_score is not touched.
"""

from __future__ import annotations

import gzip
import logging
import os
from functools import lru_cache
from typing import Optional

from .schema import KIND_ENDPOINT, canonical_mac

log = logging.getLogger("vulnmapper.hosts")

REGISTRY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.tsv.gz")
# IEEE blocks are 24 (MA-L), 28 (MA-M) or 36 (MA-S) bits: longest first.
PREFIX_LENGTHS = (9, 7, 6)
# The holder of a 24-bit block IEEE splits into MA-M / MA-S blocks: not a maker.
REGISTRY_AUTHORITY = "IEEE Registration Authority"


# --- passive: managed or not, MAC type and manufacturer ----------------------

@lru_cache(maxsize=1)
def _registry() -> dict:
    out = {}
    with gzip.open(REGISTRY, "rt", encoding="utf-8") as fh:
        for line in fh:
            if not line.startswith("#"):
                prefix, _, name = line.rstrip("\n").partition("\t")
                out[prefix] = name
    return out


def mac_type(mac) -> Optional[str]:
    """"local" when the locally administered bit is set, else "global"."""
    cmac = canonical_mac(mac)
    if cmac is None:
        return None
    return "local" if int(cmac[:2], 16) & 0x02 else "global"


def manufacturer(mac) -> Optional[str]:
    """The IEEE registry's organisation for a global MAC, else None."""
    cmac = canonical_mac(mac)
    if cmac is None or mac_type(cmac) != "global":
        return None
    registry = _registry()
    name = next((registry[cmac[:n]] for n in PREFIX_LENGTHS if cmac[:n] in registry), None)
    return None if name == REGISTRY_AUTHORITY else name


def label(graph: dict) -> dict:
    """Mark every host managed or unmanaged, add its MAC clues and
    ``metadata.coverage``. In place; returns ``graph``."""
    hosts = [n for n in graph.get("nodes") or [] if n.get("kind") == KIND_ENDPOINT]
    for node in hosts:
        node["unmanaged"] = node.get("agent_id") is None
        kind = mac_type(node.get("mac"))
        if kind is not None:
            node["mac_type"] = kind
            node["mac_vendor"] = manufacturer(node["mac"])
    managed = sum(not n["unmanaged"] for n in hosts)
    graph.setdefault("metadata", {})["coverage"] = {
        "hosts": len(hosts),
        "managed": managed,
        "unmanaged": len(hosts) - managed,
        "managed_share": round(managed / len(hosts), 3) if hosts else None,
    }
    return graph
