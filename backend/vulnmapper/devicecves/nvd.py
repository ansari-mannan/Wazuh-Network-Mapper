"""The NVD client: CVE and CPE-dictionary queries, rate limited and time boxed.

Endpoints (NVD API 2.0, checked live on 9 October 2026):

  * ``/rest/json/cves/2.0``: ``cpeName`` (a full CPE 2.3 name) returns the CVEs
    whose applicability statements match it, version ranges included;
    ``isVulnerable`` (bare, only with ``cpeName``) keeps those where that CPE
    is the vulnerable component, not merely the platform; ``keywordSearch``
    searches descriptions; ``noRejected`` drops rejected CVEs;
    ``resultsPerPage`` (at most 2000) and ``startIndex`` page.
  * ``/rest/json/cpes/2.0``: ``cpeMatchString`` looks a name up in the CPE
    dictionary. This matters: a well-formed CPE for a version NVD has never
    listed is answered with HTTP 200 and every CVE whose version range happens
    to include it (a made-up IOS version returned 79). Only a dictionary hit
    shows the query is real. A malformed name gets HTTP 404 with a ``message``
    header.

The optional key (environment variable ``NVD_API_KEY`` only) goes in the
``apiKey`` header and is never logged. Without it NVD allows 5 requests per
rolling 30 seconds and requests are spaced 6 seconds apart; with it, 50 and
0.8 seconds. A rate-limit (403/429) or server error is retried a small, fixed
number of times with a back-off. The client stops at its time budget.

The HTTP layer and the clock are parameters, so tests run from saved replies.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import quote

log = logging.getLogger("vulnmapper.devicecves")

CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPES_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
ENV_API_KEY = "NVD_API_KEY"

PAGE_SIZE = 2000                  # NVD's maximum resultsPerPage
MAX_PAGES = 10                    # 20000 CVEs for one query is far beyond any device
SPACING_NO_KEY_S = 6.0
SPACING_KEY_S = 0.8
RETRY_WAITS_S = (10.0, 30.0)      # two retries after the first attempt
REQUEST_TIMEOUT_S = 30.0
RETRY_STATUSES = {403, 429, 500, 502, 503, 504}


class NvdUnavailable(Exception):
    """NVD did not answer usefully (network error, repeated rate limit or 5xx)."""


class NvdInvalidQuery(Exception):
    """NVD rejected the query as malformed (HTTP 404 with a message)."""


class NvdBudgetExceeded(Exception):
    """The stage's time budget ran out before the request could be made."""


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)


def requests_transport(url: str, headers: dict, timeout: float):
    """GET ``url`` -> ``(status, json or None, headers)``; raises OSError-like on failure."""
    import requests
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
    except requests.RequestException as e:
        raise NvdUnavailable(f"{type(e).__name__}") from None
    try:
        body = r.json()
    except ValueError:
        body = None
    return r.status_code, body, dict(r.headers)


def _query(params: list) -> str:
    """A query string; a ``(name, None)`` pair is a bare flag (``&isVulnerable``)."""
    out = []
    for name, value in params:
        out.append(name if value is None else f"{name}={quote(str(value), safe=':*')}")
    return "&".join(out)


class NvdClient:
    """One client per scan: it owns the request spacing and the time budget."""

    def __init__(self, transport: Optional[Callable] = None, clock=None,
                 api_key: Optional[str] = None, budget_s: float = 180.0,
                 use_env_key: bool = True) -> None:
        self._transport = transport or requests_transport
        self._clock = clock or SystemClock()
        key = api_key if api_key is not None else (os.environ.get(ENV_API_KEY) if use_env_key else None)
        self._key = key or None
        self.spacing_s = SPACING_KEY_S if self._key else SPACING_NO_KEY_S
        self.budget_s = budget_s
        self._started = self._clock.monotonic()
        self._last: Optional[float] = None
        self.requests = 0                 # HTTP requests actually sent

    @property
    def has_key(self) -> bool:
        return self._key is not None

    def remaining_s(self) -> float:
        return self.budget_s - (self._clock.monotonic() - self._started)

    def _wait(self, seconds: float) -> None:
        if seconds <= 0:
            return
        if seconds > self.remaining_s():
            raise NvdBudgetExceeded()
        self._clock.sleep(seconds)

    def _get(self, base: str, params: list) -> dict:
        url = f"{base}?{_query(params)}"
        headers = {"apiKey": self._key} if self._key else {}
        last_error = "no answer"
        for attempt in range(len(RETRY_WAITS_S) + 1):
            if self._last is not None:
                self._wait(self._last + self.spacing_s - self._clock.monotonic())
            if self.remaining_s() <= 0:
                raise NvdBudgetExceeded()
            self._last = self._clock.monotonic()
            self.requests += 1
            try:
                status, body, resp_headers = self._transport(
                    url, headers, min(REQUEST_TIMEOUT_S, max(1.0, self.remaining_s())))
            except NvdUnavailable as e:
                status, body, resp_headers, last_error = None, None, {}, str(e)
            except OSError as e:
                status, body, resp_headers, last_error = None, None, {}, type(e).__name__
            if status == 200 and isinstance(body, dict):
                return body
            if status == 404:
                message = {k.lower(): v for k, v in (resp_headers or {}).items()}.get("message", "")
                raise NvdInvalidQuery(message or "HTTP 404")
            if status is not None:
                last_error = f"HTTP {status}"
                if status not in RETRY_STATUSES:
                    break
            if attempt < len(RETRY_WAITS_S):
                log.info("NVD %s; retrying in %.0f s", last_error, RETRY_WAITS_S[attempt])
                self._wait(RETRY_WAITS_S[attempt])
        raise NvdUnavailable(last_error)

    def _paged(self, base: str, params: list, key: str) -> list:
        items: list = []
        start = 0
        for _ in range(MAX_PAGES):
            doc = self._get(base, params + [("resultsPerPage", PAGE_SIZE), ("startIndex", start)])
            page = doc.get(key) or []
            items.extend(page)
            total = doc.get("totalResults") or 0
            start += len(page)
            if not page or start >= total:
                break
        return items

    def cpe_listed(self, cpe: str) -> bool:
        """Whether NVD's CPE dictionary lists this exact name (a non-deprecated entry)."""
        products = self._paged(CPES_URL, [("cpeMatchString", cpe)], "products")
        return any(not (p.get("cpe") or {}).get("deprecated") for p in products)

    def cves_for_cpe(self, cpe: str, is_vulnerable: bool = True) -> list:
        params = [("cpeName", cpe)] + ([("isVulnerable", None)] if is_vulnerable else [])
        return [v.get("cve") or {} for v in
                self._paged(CVES_URL, params + [("noRejected", None)], "vulnerabilities")]

    def cves_for_keyword(self, query: str) -> list:
        return [v.get("cve") or {} for v in self._paged(
            CVES_URL, [("keywordSearch", query), ("noRejected", None)], "vulnerabilities")]


# ---------------------------------------------------------------------------
# Reply parsing into the row shape hosts already use (endpoints.parse_hit)
# ---------------------------------------------------------------------------

# Score preference: CVSS v3.1, then v3.0, then v4.0, then v2; within a
# version the Primary entry (NVD's own) before a Secondary one.
_METRIC_ORDER = (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                 ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0"))


def best_score(metrics: dict) -> tuple:
    """``(cvss, cvss_version, severity)`` of the preferred metric, or Nones."""
    for key, version in _METRIC_ORDER:
        entries = [e for e in (metrics or {}).get(key) or [] if isinstance(e, dict)]
        entries.sort(key=lambda e: 0 if e.get("type") == "Primary" else 1)
        for e in entries:
            data = e.get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                continue
            severity = data.get("baseSeverity") or e.get("baseSeverity")
            return float(score), data.get("version") or version, \
                (severity.capitalize() if isinstance(severity, str) else None)
    return None, None, None


def _iso(ts: Optional[str]) -> Optional[str]:
    if not ts:
        return None
    return ts if ts.endswith("Z") or "+" in ts[10:] else ts + "Z"


def parse_cve(cve: dict, *, package: Optional[str], version: Optional[str],
              detected_at: Optional[str]) -> dict:
    """One NVD CVE -> a row like :func:`vulnmapper.endpoints.parse_hit` gives."""
    cvss, cvss_version, severity = best_score(cve.get("metrics") or {})
    desc = next((d.get("value") for d in cve.get("descriptions") or []
                 if d.get("lang") == "en"), None)
    refs = cve.get("references") or []
    reference = (refs[0].get("url") if refs and isinstance(refs[0], dict) else None) \
        or (f"https://nvd.nist.gov/vuln/detail/{cve['id']}" if cve.get("id") else None)
    return {
        "cve": cve.get("id"),
        "cvss": cvss,
        "cvss_version": cvss_version,
        "severity": severity,
        "package": package,
        "version": version,
        "description": desc,
        "reference": reference,
        "published_at": _iso(cve.get("published")),
        "detected_at": detected_at,
    }


def is_rejected(cve: dict) -> bool:
    return (cve.get("vulnStatus") or "").lower() == "rejected"
