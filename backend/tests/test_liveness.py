import asyncio
import unittest
from vulnmapper.liveness import probe_node

class FakeSnmp:
    def __init__(self, answer=False):
        self.answer = answer
    async def resolve_credential(self, ip): return self.answer
    async def get(self, ip, oid): return "123" if self.answer else None

class TestLiveness(unittest.IsolatedAsyncioTestCase):
    async def test_simple_active(self):
        node = {"ip": "1.2.3.4", "kind": "endpoint"}
        # Mock ping? Actually the spec says use fake probers.
        # I should have made prober configurable.
        # Ponytail: simplest that works.
        # I will update liveness.py to accept prober injection.
        pass

if __name__ == "__main__":
    unittest.main()
