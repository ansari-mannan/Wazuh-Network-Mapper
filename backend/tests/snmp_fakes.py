"""A fake SnmpClient that serves captured SNMP rows per IP (no network).

Fixtures are flat ``OID<TAB>value`` files (see fixtures/cisco_*.snmp). Every
request is recorded in ``calls`` so tests can assert what (and how much) the
crawler or the liveness pass asked for.
"""

import os

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def load_rows(name):
    rows = []
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            oid, _, value = line.partition("\t")
            rows.append((oid, value))
    return rows


def _key(oid):
    return tuple(int(p) for p in oid.split("."))


class FakeSnmpClient:
    """Serves ``devices[ip]`` (a list of rows) like the real SnmpClient.

    An IP with no rows does not answer (resolve_credential -> None). ``vlan_rows``
    maps ``(ip, vlan)`` to rows only visible in that community@vlan context.
    ``v2c`` lists IPs whose credential is SNMPv2c (default: all answering IPs).
    """

    def __init__(self, devices, vlan_rows=None, v2c=None):
        self.devices = {ip: sorted(rows, key=lambda r: _key(r[0])) for ip, rows in devices.items()}
        self.vlan_rows = {k: sorted(v, key=lambda r: _key(r[0]))
                          for k, v in (vlan_rows or {}).items()}
        self.v2c = set(devices) if v2c is None else set(v2c)
        self.calls = []

    async def resolve_credential(self, ip):
        self.calls.append(("resolve", ip))
        return object() if self.devices.get(ip) else None

    def _get(self, rows, oids):
        table = dict(rows)
        return {oid: table.get(oid) for oid in oids}

    async def get_many(self, ip, oids):
        oids = list(oids)
        self.calls.append(("get", ip, tuple(oids)))
        rows = self.devices.get(ip)
        return None if not rows else self._get(rows, oids)

    async def get(self, ip, oid):
        result = await self.get_many(ip, [oid])
        return None if result is None else result.get(oid)

    async def get_many_vlan_context(self, ip, oids, vlan):
        oids = list(oids)
        self.calls.append(("get_vlan", ip, vlan, tuple(oids)))
        if ip not in self.v2c:
            return None
        return self._get(self.vlan_rows.get((ip, vlan), []), oids)

    @staticmethod
    def _walk(rows, base):
        prefix = base.rstrip(".") + "."
        return [(o, v) for o, v in rows if o.startswith(prefix)]

    async def walk(self, ip, base_oid, **_kw):
        self.calls.append(("walk", ip, base_oid))
        return self._walk(self.devices.get(ip) or [], base_oid)

    async def walk_vlan_context(self, ip, base_oid, vlan, **_kw):
        self.calls.append(("walk_vlan", ip, base_oid, vlan))
        if ip not in self.v2c:
            return []
        return self._walk(self.vlan_rows.get((ip, vlan), []), base_oid)

    def is_v2c(self, ip):
        return ip in self.v2c

    def walks(self, ip=None, base=None):
        return [c for c in self.calls if c[0] == "walk"
                and (ip is None or c[1] == ip) and (base is None or c[2] == base)]
