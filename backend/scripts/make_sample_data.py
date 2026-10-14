#!/usr/bin/env python3
"""Developer helper: rebuild the sample in data/ from the saved test inputs.

    python3 scripts/make_sample_data.py

Runs the current pipeline on tests/fixtures/offline_scored.json and
offline_network.json (a synthetic network: made-up addresses, MACs and CVE
ids) with data/targets.sample.json as the protected assets, and writes
graph.json, vulnerabilities.json and attack_paths.json to data/. Never use lab
captures here: they hold real MACs and serials.

Nothing is downloaded and no NVD stage runs: the threat feeds and CVE records
are refused, so the sample's OVSS scores use the tool's CVSS with no KEV or
EPSS data (metadata.threat_feeds says "unavailable"). The scan runs in an
empty temporary folder, so no cache in data/ is read or written.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path.insert(0, BACKEND)

from vulnmapper.pipeline import Pipeline  # noqa: E402
from vulnmapper.scoring.feeds import FeedUnavailable  # noqa: E402

FIXTURES = os.path.join(BACKEND, "tests", "fixtures")
DATA = os.path.join(os.path.dirname(BACKEND), "data")
OUTPUTS = ("graph.json", "vulnerabilities.json", "attack_paths.json")


def refuse(url, timeout, progress=None):
    raise FeedUnavailable("the sample is built offline")


def build(out_dir: str = DATA) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copy(os.path.join(DATA, "targets.sample.json"), os.path.join(tmp, "targets.json"))
        argv = ["--scored", os.path.join(FIXTURES, "offline_scored.json"),
                "--network", os.path.join(FIXTURES, "offline_network.json"),
                "--no-device-cves", "--no-cve-vectors", "--no-name-lookup",
                "-o", os.path.join(tmp, "graph.json")]
        with contextlib.redirect_stderr(io.StringIO()):
            if Pipeline(threat_transport=refuse).run(argv) != 0:
                raise SystemExit("the pipeline failed")
        for name in OUTPUTS:
            shutil.copy(os.path.join(tmp, name), os.path.join(out_dir, name))


if __name__ == "__main__":
    build()
    print(f"wrote {', '.join(OUTPUTS)} to {DATA}")
