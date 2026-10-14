"""No test reaches the internet, whichever runner loads it: importing this
module makes the scanner's default download transport (the CISA KEV and
FIRST EPSS feeds, and the CVE Services records, which all go through
``feeds.http_get``) answer as unreachable, so a scan in a test scores with
threat feeds "unavailable" unless the test injects its own fake transport.

``python -m unittest discover -s tests`` never imports ``tests/__init__.py``,
so every test module that can reach a scan imports this one
(test_offline.py checks that they do); pytest's conftest.py imports it too.
"""

from vulnmapper.scoring import feeds

REAL_HTTP_GET = feeds.http_get      # for the tests of http_get itself


def offline(url, timeout, progress=None):
    raise feeds.FeedUnavailable("offline in tests")


feeds.http_get = offline
