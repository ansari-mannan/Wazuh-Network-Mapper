"""Command-line contract for the seed-based LLDP crawler.

The defining change from the old tool: there is **no** ``--subnet``. The crawl
seeds itself from the gateway / local LLDP neighbor and discovers the topology
on its own. Credentials are operator-supplied (never discovered); ``--community``
may be repeated to provide a set of strings to try per device.
"""

from __future__ import annotations

import argparse
from typing import Optional

import config
from config import Config, add_v3_credential, load_credentials


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="discovery_module",
        description="Seed-based LLDP topology crawler for network infrastructure "
                    "(routers/switches via SNMP/LLDP). Endpoints are out of scope.",
    )
    parser.add_argument(
        "--community",
        action="append",
        metavar="STRING",
        help="SNMPv2c community to TRY (repeatable). Also read from "
             f"${config.ENV_COMMUNITIES}/${config.ENV_COMMUNITY}. Operator-known "
             "strings only — community strings are never brute-forced.",
    )
    parser.add_argument(
        "--seed",
        action="append",
        metavar="IP",
        help="explicit seed device IP (repeatable). Optional override for when "
             "gateway detection fails or a specific start point is wanted.",
    )
    # SNMPv3 (alternative to community strings).
    parser.add_argument("--v3-user", metavar="USER", help="SNMPv3 security name")
    parser.add_argument("--v3-auth-protocol", metavar="PROTO",
                        help="SNMPv3 auth protocol (MD5/SHA/SHA256/SHA384/SHA512)")
    parser.add_argument("--v3-auth-key", metavar="KEY", help="SNMPv3 auth key")
    parser.add_argument("--v3-priv-protocol", metavar="PROTO",
                        help="SNMPv3 priv protocol (DES/AES/AES192/AES256)")
    parser.add_argument("--v3-priv-key", metavar="KEY", help="SNMPv3 priv key")

    parser.add_argument("--concurrency", type=int, default=config.DEFAULT_CONCURRENCY,
                        help=f"worker pool size (default {config.DEFAULT_CONCURRENCY})")
    parser.add_argument("--timeout", type=float, default=config.DEFAULT_TIMEOUT,
                        help=f"per-request timeout in s (default {config.DEFAULT_TIMEOUT})")
    parser.add_argument("--retries", type=int, default=config.DEFAULT_RETRIES,
                        help=f"SNMP retries per request (default {config.DEFAULT_RETRIES})")
    parser.add_argument("--max-nodes", type=int, default=config.DEFAULT_MAX_NODES,
                        help=f"safety cap on total nodes (default {config.DEFAULT_MAX_NODES})")
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT,
                        help=f"SNMP UDP port (default {config.DEFAULT_PORT})")
    parser.add_argument("--pollable-only", action="store_true",
                        help="emit only SNMP-polled infrastructure: drop every "
                             "unpollable node (no credential / no management "
                             "address) and any edge touching one.")
    parser.add_argument("-o", "--output", metavar="PATH",
                        help="write the JSON document to PATH (UTF-8, no BOM) "
                             "instead of stdout. Avoids the UTF-16 a PowerShell "
                             "'> file' redirect would produce.")
    return parser


def parse_config(argv: Optional[list[str]] = None) -> Config:
    """Parse argv into a resolved :class:`Config` (raises SystemExit on bad args)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    credentials = load_credentials(args.community)
    if args.v3_user:
        add_v3_credential(
            credentials,
            user=args.v3_user,
            auth_protocol=args.v3_auth_protocol,
            auth_key=args.v3_auth_key,
            priv_protocol=args.v3_priv_protocol,
            priv_key=args.v3_priv_key,
        )

    return Config(
        credentials=credentials,
        seeds=list(args.seed or []),
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=args.retries,
        max_nodes=args.max_nodes,
        port=args.port,
        pollable_only=args.pollable_only,
        output_path=args.output,
    )
