"""Shared, dependency-light foundations for the whole package.

Consolidates the three former ``common/`` modules into one place — these are the
contracts every other layer agrees on, with no lab I/O:

  * MAC canonicalisation — the single source of truth (``canonical_mac`` for
    comparison, ``format_mac``/``normalize_mac`` for display).
  * Environment / TLS config — ``WazuhConfig`` / ``IndexerConfig`` and the env
    var conventions (names preserved for deployment compatibility).
  * The graph schema — ``Node`` / ``Edge`` / ``CVE`` and the ``node_id`` helpers.

Nothing here imports the network/endpoint layers, so it stays import-cycle-free.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional, Union

import urllib3

# ===========================================================================
# MAC address handling — the single source of truth.
#
# Two worlds feed MACs into this pipeline and they must compare identically:
#   * Endpoints (Wazuh syscollector) report ``e4:a7:a0:25:ce:ad``.
#   * Switch forwarding tables (SNMP dot1q/dot1d) return raw hex such as
#     ``"E4 A7 A0 25 CE AD"``, ``"0xe4a7a025cead"`` or a 6-byte OctetString.
# All comparison happens on :func:`canonical_mac` (separator-stripped, lowercase
# 12-hex) and all display uses :func:`format_mac` (the colon form).
# ===========================================================================

MacInput = Union[bytes, bytearray, str, None]

# Exactly six hex octets once all separators are stripped.
_HEX12 = re.compile(r"^[0-9a-f]{12}$")
_SEPARATORS = re.compile(r"[\s:.\-]")


def canonical_mac(value: MacInput) -> Optional[str]:
    """Canonicalize any MAC representation to bare lowercase 12-hex.

    This is the comparison key — ``e4:a7:a0:25:ce:ad``, ``E4-A7-A0-25-CE-AD``,
    ``0xe4a7a025cead``, ``e4a7.a025.cead`` and the raw 6-byte OctetString all
    collapse to ``"e4a7a025cead"``. Returns ``None`` when the value is not a
    6-byte MAC (e.g. an LLDP chassis id that is a name or network address), so a
    non-MAC never false-matches.
    """
    if value is None:
        return None

    if isinstance(value, (bytes, bytearray)):
        if len(value) == 6:
            return "".join(f"{b:02x}" for b in value)
        # Could be ASCII-encoded hex inside the octet string; fall through.
        try:
            value = value.decode("ascii")
        except (UnicodeDecodeError, AttributeError):
            return None

    s = str(value).strip().lower()
    if not s:
        return None
    if s.startswith("0x"):
        s = s[2:]

    cleaned = _SEPARATORS.sub("", s)
    return cleaned if _HEX12.match(cleaned) else None


def format_mac(value: MacInput) -> Optional[str]:
    """Canonicalize to the lowercase colon form ``aa:bb:cc:dd:ee:ff``.

    The human/display form. Returns ``None`` for non-MAC values, same as
    :func:`canonical_mac`.
    """
    canonical = canonical_mac(value)
    if canonical is None:
        return None
    return ":".join(canonical[i : i + 2] for i in range(0, 12, 2))


# The network crawler historically imported ``normalize_mac`` expecting the
# colon form; keep that name pointed at the single implementation.
normalize_mac = format_mac


# ===========================================================================
# Environment / credentials / TLS config.
#
# All credentials come from the environment — the env var *names* are preserved
# from the original scripts so existing deployments keep working:
#   Wazuh Manager API:  WAZUH_HOST / WAZUH_PORT / WAZUH_USER / WAZUH_PASS
#   Wazuh Indexer:      INDEXER_HOST / INDEXER_PORT / INDEXER_USER / INDEXER_PASS
#   File paths:         AGENTS_OUT / AGENTS_IN / SCORED_OUT
# TLS verification is off by default (the lab uses self-signed certs); set
# ``VULNMAPPER_VERIFY_TLS=1`` or point ``*_CA_BUNDLE`` at a CA file to turn it on.
# ===========================================================================

# The lab uses self-signed certs; suppress the noisy warning that verify=False
# would otherwise emit on every request.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Sensible lab defaults — both code and docs agree on these. Override via env.
DEFAULT_WAZUH_HOST = "localhost"
DEFAULT_WAZUH_PORT = "55000"
DEFAULT_WAZUH_USER = "wazuh-wui"

DEFAULT_INDEXER_HOST = "192.168.100.2"
DEFAULT_INDEXER_PORT = "9200"
DEFAULT_INDEXER_USER = "admin"

# ---------------------------------------------------------------------------
# LAB CREDENTIALS (baked in by request for convenience — NOT for production).
#
# These let you run the pipeline with no env vars. They are real lab secrets in
# source control: rotate them before this repo leaves the lab, and prefer the
# env vars (WAZUH_PASS / INDEXER_PASS) which still override these defaults.
# ---------------------------------------------------------------------------
DEFAULT_WAZUH_PASS = "zdKD40.djaynryDwDfz4vGUDX1TRfYkY"
DEFAULT_INDEXER_PASS = "Cyfor@123."


def _truthy(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def tls_verify(ca_bundle_env: str) -> Union[bool, str]:
    """Resolve the ``verify=`` value for a requests call.

    Returns the path to a CA bundle if one is configured, else ``True`` when
    ``VULNMAPPER_VERIFY_TLS`` is set, else ``False`` (the lab default). This is
    the single place the lab-only ``verify=False`` decision lives.
    """
    bundle = os.environ.get(ca_bundle_env)
    if bundle:
        return bundle
    return _truthy(os.environ.get("VULNMAPPER_VERIFY_TLS"))


@dataclass
class WazuhConfig:
    """Connection settings for the Wazuh Manager API (port 55000)."""

    host: str
    port: str
    user: str
    password: str
    verify: Union[bool, str] = False

    @classmethod
    def from_env(cls) -> "WazuhConfig":
        # Env wins; falls back to the baked-in lab password for convenience.
        return cls(
            host=os.environ.get("WAZUH_HOST", DEFAULT_WAZUH_HOST),
            port=os.environ.get("WAZUH_PORT", DEFAULT_WAZUH_PORT),
            user=os.environ.get("WAZUH_USER", DEFAULT_WAZUH_USER),
            password=os.environ.get("WAZUH_PASS", DEFAULT_WAZUH_PASS),
            verify=tls_verify("WAZUH_CA_BUNDLE"),
        )


@dataclass
class IndexerConfig:
    """Connection settings for the Wazuh Indexer / OpenSearch (port 9200)."""

    host: str
    port: str
    user: str
    password: str
    verify: Union[bool, str] = False

    @classmethod
    def from_env(cls) -> "IndexerConfig":
        # Env wins; falls back to the baked-in lab password for convenience.
        return cls(
            host=os.environ.get("INDEXER_HOST", DEFAULT_INDEXER_HOST),
            port=os.environ.get("INDEXER_PORT", DEFAULT_INDEXER_PORT),
            user=os.environ.get("INDEXER_USER", DEFAULT_INDEXER_USER),
            password=os.environ.get("INDEXER_PASS", DEFAULT_INDEXER_PASS),
            verify=tls_verify("INDEXER_CA_BUNDLE"),
        )


# ===========================================================================
# The graph schema — Node / Edge / CVE and the node_id helpers.
#
# Every node carries exactly one stable, unique ``node_id`` that edges reference;
# we never key on hostname or IP (both are soft and collide):
#   * endpoints  -> ``endpoint:<agent_id>``   (the Wazuh agent id; hard + unique)
#   * devices    -> ``device:<chassis_id>``   (the LLDP/SNMP chassis id)
#   * fdb hosts  -> ``host:<mac>``            (reconstructed from switch tables)
# ===========================================================================

KIND_ENDPOINT = "endpoint"
KIND_DEVICE = "device"

# discovery_method values stamped by each source.
DISCOVERY_WAZUH = "wazuh"
DISCOVERY_SNMP_LLDP = "snmp_lldp"
# discovery_method for a host reconstructed purely from switch/router tables.
DISCOVERY_SNMP_FDB = "snmp_fdb"

# edge relationship types.
EDGE_LLDP = "lldp"                 # device <-> device adjacency (LLDP)
EDGE_ENDPOINT_LINK = "endpoint_link"  # endpoint -> switch access port


def endpoint_node_id(agent_id: Any) -> str:
    """Stable node id for an endpoint, from its Wazuh agent id."""
    return f"endpoint:{agent_id}"


def device_node_id(chassis_id: Any) -> str:
    """Stable node id for a network device, from its LLDP/SNMP chassis id."""
    return f"device:{chassis_id}"


def host_node_id(mac: Any) -> str:
    """Stable node id for a host discovered only from FDB/ARP (no agent, no LLDP)."""
    return f"host:{mac}"


@dataclass
class CVE:
    """One vulnerability finding attached to an endpoint node."""

    cve: Optional[str] = None
    cvss: Optional[float] = None
    cvss_version: Optional[str] = None
    severity: Optional[str] = None
    package: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "cve": self.cve,
            "cvss": self.cvss,
            "cvss_version": self.cvss_version,
            "severity": self.severity,
            "package": self.package,
            "version": self.version,
            "description": self.description,
        }


@dataclass
class Edge:
    """A graph edge referencing nodes by ``node_id`` (never hostname/IP).

    ``type`` is :data:`EDGE_LLDP` for an inter-device adjacency or
    :data:`EDGE_ENDPOINT_LINK` for an endpoint hanging off a switch access port.
    For an endpoint link, ``local_port`` is the switch access port and
    ``confidence`` records how certain the placement is
    (``resolved`` / ``tiebreak`` / ``fallback``).
    """

    source: str            # node_id
    target: str            # node_id
    type: str
    local_port: Optional[str] = None
    remote_port: Optional[str] = None
    confidence: Optional[str] = None

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "source": self.source,
            "target": self.target,
            "type": self.type,
        }
        if self.local_port is not None:
            out["local_port"] = self.local_port
        if self.remote_port is not None:
            out["remote_port"] = self.remote_port
        if self.confidence is not None:
            out["confidence"] = self.confidence
        return out


@dataclass
class Node:
    """A unified graph node — an endpoint or a network device.

    The dataclass is the superset of both worlds' fields; a field that does not
    apply to a given kind stays ``None`` / its default. ``to_dict`` emits a
    stable shape with ``node_id`` first.
    """

    node_id: str
    kind: str
    discovery_method: str
    # ---- shared base schema ----
    ip: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware: Optional[str] = None
    serial: Optional[str] = None
    mac: Optional[str] = None
    status: Optional[str] = None
    # ``role`` is what the node IS (l3-switch / l2-switch / router / access-point
    # / phone / station / host / "Unknown Network Device"), derived purely from
    # the LLDP capability bitmap — no vendor/model guessing. Distinct from
    # ``kind`` (which records which discovery track found it).
    role: Optional[str] = None
    # ---- endpoint extras ----
    agent_id: Optional[str] = None
    risk_score: float = 0
    # Highest CVSS across ``top_cves`` (null when unscored / no CVEs). Distinct
    # from ``risk_score``, which remains the field of record for ranking and edge
    # weights; ``max_cvss`` is exposed for consumers that key on raw CVSS.
    max_cvss: Optional[float] = None
    top_cves: list = field(default_factory=list)
    # True when this endpoint's IP collides with a currently-active endpoint and
    # its own status is disconnected (a stale Wazuh agent — IP reassigned).
    stale: bool = False
    # ---- device extras ----
    chassis_id: Optional[str] = None
    pollable: Optional[bool] = None
    neighbor_ports: Optional[list] = None
    uplink_ports: Optional[list] = None
    port_status: Optional[dict] = None
    fdb: Optional[list] = None
    # ---- discovery stamping (set by the assembler) ----
    discovery_order: Optional[int] = None
    parent_id: Optional[str] = None

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "node_id": self.node_id,
            "kind": self.kind,
            "ip": self.ip,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "model": self.model,
            "firmware": self.firmware,
            "serial": self.serial,
            "mac": self.mac,
            "discovery_method": self.discovery_method,
            "status": self.status,
            "role": self.role,
            "risk_score": self.risk_score,
            "max_cvss": self.max_cvss,
            "discovery_order": self.discovery_order,
            "parent_id": self.parent_id,
        }
        if self.kind == KIND_ENDPOINT:
            out["agent_id"] = self.agent_id
            out["stale"] = self.stale
            out["top_cves"] = self.top_cves
        else:
            out["chassis_id"] = self.chassis_id
            out["pollable"] = self.pollable
            if self.neighbor_ports is not None:
                out["neighbor_ports"] = self.neighbor_ports
            if self.uplink_ports is not None:
                out["uplink_ports"] = self.uplink_ports
            if self.port_status is not None:
                out["port_status"] = self.port_status
        return out
