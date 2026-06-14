"""Programmatic entry point for the crawl, shared by the CLI and the pipeline.

Holds the orchestration that used to live in the crawler's ``__main__``: build
the SNMP client, seed, run the bounded worker pool, and assemble the output
document. The pipeline calls :func:`crawl_document` to get the network side as a
Python dict; the CLI (``__main__``) wraps the same flow with stdout/file output.
"""

from __future__ import annotations

import asyncio
import logging

from . import output, seed
from .config import Config
from .crawler import Crawler
from .snmp_client import SnmpClient

log = logging.getLogger("discovery")


async def run(cfg: Config) -> dict:
    """Run the crawl described by ``cfg`` and return the output document."""
    if not cfg.credentials:
        log.error(
            "no SNMP credentials supplied. Pass --community / --v3-user (or set "
            "$SNMP_COMMUNITIES). Emitting empty topology."
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


def crawl_document(cfg: Config) -> dict:
    """Synchronous wrapper: run the crawl and always return a valid document."""
    try:
        return asyncio.run(run(cfg))
    except Exception:
        log.exception("crawl failed; emitting empty topology")
        return output.build_document([], [])
