"""The crawl on its own: ``python -m vulnmapper.network --community X``.

stdout carries only the JSON network document; progress goes to stderr. The
full pipeline runs the same crawl through ``crawl.crawl_document``.
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional

from ..common import setup_logging
from .config import (DEFAULT_CONCURRENCY, DEFAULT_MAX_NODES, DEFAULT_PORT, DEFAULT_RETRIES,
                     DEFAULT_TIMEOUT, ENV_COMMUNITIES, ENV_COMMUNITY, Config,
                     add_v3_credential, load_credentials)
from .crawl import crawl_document
from .document import emit, write

log = logging.getLogger("discovery")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="discovery_module",
        description="Seed-based LLDP topology crawler for network infrastructure "
                    "(routers/switches via SNMP/LLDP). Endpoints are out of scope.",
    )
    parser.add_argument(
        "--community", action="append", metavar="STRING",
        help="SNMPv2c community to TRY (repeatable). Also read from "
             f"${ENV_COMMUNITIES}/${ENV_COMMUNITY}. Operator-known "
             "strings only — community strings are never brute-forced.",
    )
    parser.add_argument(
        "--seed", action="append", metavar="IP",
        help="explicit seed device IP (repeatable). Optional override for when "
             "gateway detection fails or a specific start point is wanted.",
    )
    parser.add_argument("--v3-user", metavar="USER", help="SNMPv3 security name")
    parser.add_argument("--v3-auth-protocol", metavar="PROTO",
                        help="SNMPv3 auth protocol (MD5/SHA/SHA256/SHA384/SHA512)")
    parser.add_argument("--v3-auth-key", metavar="KEY", help="SNMPv3 auth key")
    parser.add_argument("--v3-priv-protocol", metavar="PROTO",
                        help="SNMPv3 priv protocol (DES/AES/AES192/AES256)")
    parser.add_argument("--v3-priv-key", metavar="KEY", help="SNMPv3 priv key")

    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                        help=f"worker pool size (default {DEFAULT_CONCURRENCY})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"per-request timeout in s (default {DEFAULT_TIMEOUT})")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                        help=f"SNMP retries per request (default {DEFAULT_RETRIES})")
    parser.add_argument("--max-nodes", type=int, default=DEFAULT_MAX_NODES,
                        help=f"safety cap on total nodes (default {DEFAULT_MAX_NODES})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"SNMP UDP port (default {DEFAULT_PORT})")
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
    args = build_parser().parse_args(argv)
    credentials = load_credentials(args.community)
    if args.v3_user:
        add_v3_credential(credentials, user=args.v3_user,
                          auth_protocol=args.v3_auth_protocol, auth_key=args.v3_auth_key,
                          priv_protocol=args.v3_priv_protocol, priv_key=args.v3_priv_key)
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


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    cfg = parse_config(argv)
    document = crawl_document(cfg)

    pollable = sum(1 for n in document["nodes"] if n["pollable"])
    log.info("SUMMARY: %d node(s) (%d pollable), %d edge(s).",
             len(document["nodes"]), pollable, len(document["edges"]))

    if cfg.output_path:
        write(document, cfg.output_path)
        log.info("wrote topology to %s", cfg.output_path)
    else:
        emit(document)
    return 0


if __name__ == "__main__":
    sys.exit(main())
