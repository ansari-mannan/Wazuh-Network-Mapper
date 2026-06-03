"""Standalone connectivity check — query ONE IP and print raw SNMP values.

Run this against a known device BEFORE attempting a full subnet sweep, to
confirm SNMP reachability and the community string:

    python test_one.py --ip 192.168.1.1 --community public

It prints the raw sysDescr and sysObjectID (and sysName) so you can eyeball
whether the device answers and what it looks like. No parsing, no JSON — just
the raw values. Output goes to stdout; this script is for humans, not pipes.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from clients.snmp_client import (
    OID_SYS_DESCR,
    OID_SYS_NAME,
    OID_SYS_OBJECT_ID,
    SnmpClient,
)


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", required=True, help="IP address of one device to probe")
    parser.add_argument("--community", required=True, help="SNMPv2c community string")
    parser.add_argument(
        "--timeout", type=float, default=1.0, help="per-request timeout in seconds"
    )
    parser.add_argument(
        "--port", type=int, default=161, help="SNMP UDP port (default 161)"
    )
    args = parser.parse_args()

    client = SnmpClient(
        args.community, port=args.port, timeout=args.timeout, retries=0
    )

    print(f"Probing {args.ip} ...", file=sys.stderr)
    values = await client.get_many(
        args.ip, [OID_SYS_DESCR, OID_SYS_OBJECT_ID, OID_SYS_NAME]
    )

    if values is None:
        print(f"No SNMP response from {args.ip}.", file=sys.stderr)
        return 1

    print(f"sysDescr    ({OID_SYS_DESCR})    = {values.get(OID_SYS_DESCR)!r}")
    print(f"sysObjectID ({OID_SYS_OBJECT_ID}) = {values.get(OID_SYS_OBJECT_ID)!r}")
    print(f"sysName     ({OID_SYS_NAME})    = {values.get(OID_SYS_NAME)!r}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
