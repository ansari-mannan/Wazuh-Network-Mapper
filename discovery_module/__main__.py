"""Seed-based LLDP topology crawler — entry point.

Discovers network infrastructure (routers/switches via SNMP/LLDP) by crawling
LLDP neighbor tables outward from a seed, with no subnet argument. Endpoints are
out of scope (handled by a separate Wazuh-agent pipeline).

    python -m discovery_module --community cyfor123 > output.json

stdout carries ONLY the final JSON document so the Node.js plugin layer can
parse it; all progress/diagnostics go to stderr. The crawl fails fast and loud
on an unreachable seed and always emits a valid (possibly empty) JSON document.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

# Make sibling modules importable whether launched as `python -m discovery_module`
# or `python __main__.py`.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import output
import seed
from cli import parse_config
from config import Config
from crawler import Crawler
from snmp_client import SnmpClient

log = logging.getLogger("discovery")


def _setup_logging() -> None:
    # Everything human-readable goes to stderr; stdout is reserved for JSON.
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


async def run(cfg: Config) -> dict:
    if not cfg.credentials:
        log.error(
            "no SNMP credentials supplied. Pass --community / --v3-user (or set "
            "$%s). Emitting empty topology.", "SNMP_COMMUNITIES",
        )
        return output.build_document([], [])

    seeds = seed.discover_seeds(cfg.seeds)
    if not seeds:
        log.error(
            "no seed device found (no default gateway, no local LLDP neighbor, "
            "no --seed). Emitting empty topology."
        )
        return output.build_document([], [])

    log.info("seeds: %s", ", ".join(seeds))
    log.info(
        "crawl config: concurrency=%d timeout=%.1fs retries=%d max_nodes=%d port=%d "
        "credentials=%s",
        cfg.concurrency, cfg.timeout, cfg.retries, cfg.max_nodes, cfg.port,
        ", ".join(c.label for c in cfg.credentials),
    )

    client = SnmpClient(
        cfg.credentials, port=cfg.port, timeout=cfg.timeout, retries=cfg.retries
    )
    crawler = Crawler(
        client,
        concurrency=cfg.concurrency,
        max_nodes=cfg.max_nodes,
        queue_maxsize=cfg.queue_maxsize,
    )
    await crawler.seed(seeds)
    devices, links = await crawler.run()
    return output.build_document(devices, links, pollable_only=cfg.pollable_only)


def main(argv: list[str] | None = None) -> int:
    _setup_logging()
    cfg = parse_config(argv)

    try:
        document = asyncio.run(run(cfg))
    except Exception:
        # Last-resort guard: downstream must always get parseable JSON.
        log.exception("crawl failed; emitting empty topology")
        document = output.build_document([], [])

    pollable = sum(1 for n in document["nodes"] if n["pollable"])
    log.info(
        "SUMMARY: %d node(s) (%d pollable), %d edge(s).",
        len(document["nodes"]), pollable, len(document["edges"]),
    )

    if cfg.output_path:
        output.write(document, cfg.output_path)
        log.info("wrote topology to %s", cfg.output_path)
    else:
        output.emit(document)
    return 0


if __name__ == "__main__":
    sys.exit(main())
