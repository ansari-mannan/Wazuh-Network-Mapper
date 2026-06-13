"""CLI for the network crawler: ``python -m vulnmapper.network --community X``.

stdout carries ONLY the final JSON topology document so the Node.js plugin layer
can parse it; all progress/diagnostics go to stderr. Within the unified pipeline
this stage is normally driven via :func:`runner.crawl_document` instead.
"""

from __future__ import annotations

import logging
import sys

from .crawl import crawl_document, emit, parse_config, write

log = logging.getLogger("discovery")


def _setup_logging() -> None:
    # Everything human-readable goes to stderr; stdout is reserved for JSON.
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main(argv: list[str] | None = None) -> int:
    _setup_logging()
    cfg = parse_config(argv)

    document = crawl_document(cfg)

    pollable = sum(1 for n in document["nodes"] if n["pollable"])
    log.info(
        "SUMMARY: %d node(s) (%d pollable), %d edge(s).",
        len(document["nodes"]), pollable, len(document["edges"]),
    )

    if cfg.output_path:
        write(document, cfg.output_path)
        log.info("wrote topology to %s", cfg.output_path)
    else:
        emit(document)
    return 0


if __name__ == "__main__":
    sys.exit(main())
