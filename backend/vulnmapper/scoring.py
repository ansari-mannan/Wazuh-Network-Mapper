"""One base risk score per endpoint, from its CVE list.

:func:`base_score` is the only public function. Its signature is a contract: a
teammate's enrichment framework will later replace the body (and may add inputs
of its own), so callers must depend on nothing but ``base_score(cves)``.

The current body is a placeholder: about 70% of the score is how bad the worst
CVE is, and 30% is how many CVEs there are, with diminishing returns.
"""

from __future__ import annotations

import math
from typing import Optional

# CVSS v3 severity bands (lower bound of each band; below MEDIUM_MIN is low).
CRITICAL_MIN = 9.0
HIGH_MIN = 7.0
MEDIUM_MIN = 4.0

# Weight of one distinct CVE in each band, for the volume term.
WEIGHT_CRITICAL = 10
WEIGHT_HIGH = 5
WEIGHT_MEDIUM = 2
WEIGHT_LOW = 1

# Weighted count at which the volume term saturates (10000 = 1000 criticals).
# Real Windows hosts carry hundreds to thousands of CVEs; at 1000 they all
# saturated near the top of the scale.
VOLUME_SATURATION = 10000

# Share of the final score taken by the worst CVE vs. the CVE volume.
SEVERITY_SHARE = 0.7
VOLUME_SHARE = 0.3

MAX_SCORE = 10.0


def _weight(cvss: float) -> int:
    if cvss >= CRITICAL_MIN:
        return WEIGHT_CRITICAL
    if cvss >= HIGH_MIN:
        return WEIGHT_HIGH
    if cvss >= MEDIUM_MIN:
        return WEIGHT_MEDIUM
    return WEIGHT_LOW


def base_score(cves: Optional[list]) -> Optional[float]:
    """Base risk score for one host, 0.0-10.0 rounded to one decimal.

    ``cves`` is every CVE row for the host (dicts with ``cve`` (the id),
    ``cvss``, ``severity``, ``package``; descriptions are not needed). The index
    holds one row per CVE and package, so rows are counted by distinct CVE id,
    each at its highest score. A row with no score adds nothing.

    Returns None when ``cves`` is None (the host could not be scored) and 0.0
    for an empty list (scanned, nothing found).

    CONTRACT: this signature is fixed. A teammate's enrichment framework will
    replace the body only. Placeholder formula (constants at the top of the
    module)::

        weighted = 10*critical + 5*high + 2*medium + 1*low   (distinct CVEs)
        volume   = min(1, log10(1 + weighted) / log10(1 + 10000))
        score    = 0.7 * max_cvss + 0.3 * 10 * volume
    """
    if cves is None:
        return None

    worst: dict = {}
    for i, row in enumerate(cves):
        cvss = row.get("cvss")
        if cvss is None:
            continue
        key = row.get("cve") or ("#row", i)  # a row with no id counts on its own
        if key not in worst or cvss > worst[key]:
            worst[key] = cvss
    if not worst:
        return 0.0

    weighted = sum(_weight(cvss) for cvss in worst.values())
    volume = min(1.0, math.log10(1 + weighted) / math.log10(1 + VOLUME_SATURATION))
    score = SEVERITY_SHARE * max(worst.values()) + VOLUME_SHARE * MAX_SCORE * volume
    return round(min(MAX_SCORE, max(0.0, score)), 1)
