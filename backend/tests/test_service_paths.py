"""Inside the Wazuh dashboard the scanner runs as the wazuh-dashboard user,
which can write only graphPath's folder (/var/lib/vulnmapper): every file a
scan writes must land there (scripts/install-wazuh.sh). The named caches
(osv-cache, cve-records, nmap-cache, kev, epss) all go in cache_folder()."""
import os
import unittest

from vulnmapper.pipeline import ScanContext, build_parser

DATA = "/var/lib/vulnmapper"


class FilesBesideTheGraph(unittest.TestCase):
    def test_outputs_and_caches_are_in_the_graph_folder(self):
        scan = ScanContext(build_parser().parse_args(["-o", f"{DATA}/graph.json"]))
        for path in (scan.vulns_path, scan.paths_out, scan.targets_path, scan.nvd_cache_path()):
            self.assertEqual(os.path.dirname(path), DATA)
        self.assertEqual(scan.cache_folder(), DATA)


if __name__ == "__main__":
    unittest.main()
