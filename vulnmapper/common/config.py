"""Env-var loading conventions and shared HTTP helpers for the endpoint layer.

All credentials come from the environment — nothing is hard-coded. The env var
*names* are preserved from the original two scripts so existing deployments keep
working:

  Wazuh Manager API:  WAZUH_HOST / WAZUH_PORT / WAZUH_USER / WAZUH_PASS
  Wazuh Indexer:      INDEXER_HOST / INDEXER_PORT / INDEXER_USER / INDEXER_PASS
  File paths:         AGENTS_OUT / AGENTS_IN / SCORED_OUT

TLS verification is off by default because the lab Wazuh stack uses self-signed
certificates — but it is an *explicit* choice with a clear upgrade path: set
``VULNMAPPER_VERIFY_TLS=1`` (or point ``*_CA_BUNDLE`` at a CA file) to turn it
on without touching code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Union

import urllib3

# The lab uses self-signed certs; suppress the noisy warning that verify=False
# would otherwise emit on every request. Logging stays the channel for anything
# operationally meaningful.
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
