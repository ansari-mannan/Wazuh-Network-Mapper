#!/usr/bin/env python3
"""Developer helper: build the MAC manufacturer registry the scan ships with.

Reads IEEE's public registries of MAC address blocks (MA-L, 24-bit; MA-M,
28-bit; MA-S, 36-bit) and writes ``vulnmapper/oui.tsv.gz``: one
``<hex prefix>\\t<organisation>`` line per block, after a header naming the
source files and the date. The scan reads that file and never downloads
anything; run this again to refresh it.

    python3 scripts/build_oui.py                  # download from IEEE
    python3 scripts/build_oui.py oui.csv mam.csv oui36.csv   # local copies
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import os
import sys
import urllib.request
from datetime import date

URLS = ("https://standards-oui.ieee.org/oui/oui.csv",
        "https://standards-oui.ieee.org/oui28/mam.csv",
        "https://standards-oui.ieee.org/oui36/oui36.csv")
# IEEE's server rejects requests without a browser's headers.
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                         "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
           "Accept": "text/html,text/csv,*/*", "Accept-Language": "en-US,en;q=0.9"}
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vulnmapper", "oui.tsv.gz")


def _read(source: str) -> str:
    if source.startswith("https://"):
        with urllib.request.urlopen(urllib.request.Request(source, headers=HEADERS),
                                    timeout=60) as resp:
            return resp.read().decode("utf-8")
    with open(source, encoding="utf-8") as fh:
        return fh.read()


def parse(text: str) -> dict:
    """``{hex prefix: organisation}`` from one IEEE CSV (Registry, Assignment, Organization Name, ...)."""
    out = {}
    for row in csv.DictReader(io.StringIO(text)):
        prefix = (row.get("Assignment") or "").strip().lower()
        name = " ".join((row.get("Organization Name") or "").split())
        if prefix and name and all(c in "0123456789abcdef" for c in prefix):
            out[prefix] = name
    if not out:
        raise SystemExit("no rows read: not an IEEE registry CSV")
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("sources", nargs="*", default=list(URLS),
                        help="IEEE CSV files or URLs (default: download MA-L, MA-M, MA-S)")
    args = parser.parse_args(argv)
    blocks: dict = {}
    for source in args.sources:
        blocks.update(parse(_read(source)))
    header = ["# MAC address block -> organisation, from the IEEE Registration Authority",
              *(f"# source: {s}" for s in args.sources),
              f"# date: {date.today().isoformat()}",
              f"# blocks: {len(blocks)}"]
    lines = header + [f"{p}\t{n}" for p, n in sorted(blocks.items())]
    # mtime=0 keeps the file byte-identical for identical input
    with gzip.GzipFile(OUT, "wb", mtime=0) as fh:
        fh.write(("\n".join(lines) + "\n").encode("utf-8"))
    print(f"{len(blocks)} blocks -> {os.path.normpath(OUT)} ({os.path.getsize(OUT)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
