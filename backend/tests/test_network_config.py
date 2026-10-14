"""SNMP credentials from the environment: the form's community is never split,
and a malformed list exits cleanly without echoing the secret."""

import unittest
from unittest import mock

from vulnmapper.network.config import load_credentials


def communities(env: dict) -> list:
    with mock.patch.dict("os.environ", env, clear=True):
        return [c.community for c in load_credentials(None)]


class TestLoadCredentials(unittest.TestCase):
    def test_form_community_is_taken_whole_and_first(self):
        self.assertEqual(communities({"VULNMAPPER_SNMP_COMMUNITY": "my secret,x'y",
                                      "SNMP_COMMUNITIES": "a,b"}),
                         ["my secret,x'y", "a", "b"])

    def test_single_community_is_one_string(self):
        self.assertEqual(communities({"SNMP_COMMUNITY": " a b "}), ["a b"])

    def test_list_is_still_split(self):
        self.assertEqual(communities({"SNMP_COMMUNITIES": "a, b 'c d'"}), ["a", "b", "c d"])

    def test_unbalanced_quote_exits_without_the_value(self):
        with self.assertRaises(SystemExit) as cm:
            communities({"SNMP_COMMUNITIES": "it's,ab"})
        self.assertIn("unbalanced quote", str(cm.exception.code))
        self.assertNotIn("it's", str(cm.exception.code))


if __name__ == "__main__":
    unittest.main()
