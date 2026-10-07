"""base_score: the placeholder per-host score (contract: base_score(cves))."""

import unittest

from vulnmapper.scoring import base_score


def crit(n, cvss=9.8):
    return [{"cve": f"CVE-C-{i}", "cvss": cvss, "severity": "Critical", "package": "p"}
            for i in range(n)]


class TestBaseScore(unittest.TestCase):
    def test_none_means_not_scored(self):
        self.assertIsNone(base_score(None))

    def test_empty_list_is_zero(self):
        self.assertEqual(base_score([]), 0.0)

    def test_one_critical(self):
        self.assertEqual(base_score(crit(1)), 7.9)

    def test_many_criticals(self):
        self.assertEqual(base_score(crit(100)), 9.9)

    def test_volume_saturates(self):
        self.assertEqual(base_score(crit(500)), base_score(crit(100)))

    def test_medium_only_host(self):
        rows = [{"cve": f"CVE-M-{i}", "cvss": 6.5, "severity": "Medium", "package": "p"}
                for i in range(5)]
        # weighted 10 -> volume log10(11)/log10(1001) = 0.347; 0.7*6.5 + 3*0.347
        self.assertEqual(base_score(rows), 5.6)

    def test_counts_distinct_cves_not_packages(self):
        rows = [{"cve": "CVE-1", "cvss": 9.8, "package": "a"},
                {"cve": "CVE-1", "cvss": 9.8, "package": "b"},
                {"cve": "CVE-1", "cvss": 9.8, "package": "c"}]
        self.assertEqual(base_score(rows), base_score(crit(1)))

    def test_unscored_rows_add_nothing(self):
        self.assertEqual(base_score([{"cve": "CVE-1", "cvss": None}]), 0.0)
        self.assertEqual(base_score(crit(1) + [{"cve": "CVE-X", "cvss": None}]), 7.9)

    def test_range(self):
        for rows in (crit(1, 0.1), crit(5000, 10.0)):
            self.assertTrue(0.0 <= base_score(rows) <= 10.0)


if __name__ == "__main__":
    unittest.main()
