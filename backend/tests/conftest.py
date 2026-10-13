"""No test reaches the internet: the threat feeds and CVE records answer as
unreachable unless a test passes its own transport."""

import pytest

from vulnmapper.scoring import feeds


def _offline(url, timeout):
    raise feeds.FeedUnavailable("offline in tests")


@pytest.fixture(autouse=True)
def no_threat_downloads(monkeypatch):
    monkeypatch.setattr(feeds, "http_get", _offline)
