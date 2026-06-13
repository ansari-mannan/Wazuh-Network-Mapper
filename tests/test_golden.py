"""Golden regression test — the spine of the consolidation refactor.

Re-runs ``assemble()`` on the SAME fixed inputs the golden was frozen from
(``tools/_freeze_golden.py``) and asserts the output is identical to the frozen
``tests/golden/*.expected.json`` — both as parsed objects and as serialized text.
The only normalised field is ``metadata.scan_time`` (``datetime.now``).

This must stay green after every refactor step. A divergence here means structure
changed behaviour — which the refactor must never do.
"""

import json
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_GOLDEN = os.path.join(_HERE, "golden")
sys.path.insert(0, _HERE)  # import sibling test modules + the freeze helper's scenarios

from vulnmapper.assemble.merge import assemble  # noqa: E402

FROZEN_SCAN_TIME = "FROZEN_SCAN_TIME"


def _normalise(doc: dict) -> dict:
    meta = doc.get("metadata")
    if isinstance(meta, dict) and "scan_time" in meta:
        meta["scan_time"] = FROZEN_SCAN_TIME
    return doc


def _scenarios():
    import test_assemble
    return [("parenting_ladder", test_assemble.endpoints(), test_assemble.network_doc())]


class TestGolden(unittest.TestCase):
    def test_assemble_matches_frozen_golden(self):
        for name, endpoints, network_doc in _scenarios():
            with self.subTest(scenario=name):
                path = os.path.join(_GOLDEN, f"{name}.expected.json")
                self.assertTrue(os.path.exists(path),
                                f"missing golden {path}; run tools/_freeze_golden.py")
                expected_text = open(path, encoding="utf-8").read()
                expected = json.loads(expected_text)

                produced = _normalise(assemble(endpoints, network_doc))
                produced_text = json.dumps(produced, indent=2, sort_keys=False) + "\n"

                # Parsed-object equality (field values) ...
                self.assertEqual(produced, expected)
                # ... and serialized-text equality (field order + formatting).
                self.assertEqual(produced_text, expected_text)


if __name__ == "__main__":
    unittest.main()
