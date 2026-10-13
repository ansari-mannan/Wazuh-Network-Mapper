"""OVSS, the scanner's per-finding risk score, and the CVSS severity bands.

    feeds.py        CISA KEV and FIRST EPSS, downloaded at most once a day
    cvss_select.py  CVE records from cve.org (CNA / ADP scores), cached, and
                    the choice of the CVSS score each finding is scored from
    ovss.py         the formula, the tiers and the finding and node records
    stage.py        the pipeline stage that puts them together
"""

# CVSS v3 severity bands (lower bound of each band; below MEDIUM_MIN is low).
CRITICAL_MIN = 9.0
HIGH_MIN = 7.0
MEDIUM_MIN = 4.0
