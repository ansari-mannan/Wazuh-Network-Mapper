#!/usr/bin/env python3
"""Developer helper: read net-snmp captures (``snmpwalk -On`` output) as rows.

The lab captures in ~/dev/captures never go into git. This turns the rows a
feature needs into test fixtures (OID<TAB>value, the format of
tests/fixtures/*.snmp) and lets other developer scripts read them the way the
crawler would. Values are rendered as vulnmapper's SnmpClient renders them
live: octet strings as 0x<hex>, text unquoted, numbers bare, timeticks as the
raw count, OIDs without the leading dot. net-snmp error lines (the HP switch
answers one table out of order, which stops snmpwalk) are skipped.

    python3 scripts/captures.py --fixtures tests/fixtures ~/dev/captures

writes checklist_<device>.snmp for each captured device (l3, l2, hp, ap).
"""

from __future__ import annotations

import argparse
import os
import re
import sys

_LINE = re.compile(r"^(\.[0-9.]+) = (.*)$")

# The rows the configuration checks read (see vulnmapper/checklist/tables.py).
CHECKLIST_SUBTREES = (
    "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0",
    "1.3.6.1.2.1.6.13.1.1", "1.3.6.1.2.1.6.20.1.4",
    "1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.3", "1.3.6.1.2.1.2.2.1.7",
    "1.3.6.1.2.1.2.2.1.8", "1.3.6.1.2.1.2.2.1.9", "1.3.6.1.2.1.31.1.1.1.1",
    "1.3.6.1.2.1.17.1.4.1.2", "1.3.6.1.2.1.17.7.1.4.5.1.1",
    "1.3.6.1.4.1.9.9.68.1.2.2.1.2",
    "1.3.6.1.4.1.9.9.315.1.1.3.0", "1.3.6.1.4.1.9.9.315.1.2.1.1.1",
    "1.3.6.1.4.1.9.9.82.1.9.1.0", "1.3.6.1.4.1.9.9.82.1.9.4.0",
    "1.3.6.1.4.1.9.9.82.1.9.3.1.3", "1.3.6.1.4.1.9.9.82.1.9.3.1.4",
)
CAPTURE_FILES = ("system", "tcp", "interfaces", "bridge-stp", "vlan", "portsecurity", "stp-ext")
DEVICES = ("l3", "l2", "hp", "ap")


def _render(raw: str) -> str:
    if raw == '""':
        return ""
    kind, _, value = raw.partition(": ")
    if kind == "Hex-STRING":
        return "0x" + "".join(value.split()).lower()
    if kind == "STRING":
        return value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value
    if kind == "OID":
        return value.lstrip(".")
    if kind == "Timeticks":
        match = re.search(r"\((\d+)\)", value)
        return match.group(1) if match else value
    return value if _ else raw


def _open_string(raw: str) -> bool:
    """A quoted string value whose closing quote is still to come."""
    return raw.startswith('STRING: "') and not (len(raw) > len('STRING: "') and raw.endswith('"'))


def read_capture(path: str) -> list:
    """``[(oid, value), ...]`` from one capture file."""
    rows, current = [], None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            match = _LINE.match(line)
            if match:
                if current:
                    rows.append(current)
                current = [match.group(1).lstrip("."), match.group(2)]
            elif current is not None and _open_string(current[1]):
                current[1] += " " + line.strip()     # multi-line quoted string
    if current:
        rows.append(current)
    out = []
    for oid, raw in rows:
        if raw.startswith(("No Such Object", "No Such Instance", "No more variables")):
            continue
        out.append((oid, " ".join(_render(raw).split()) if raw.startswith("STRING") else _render(raw)))
    return out


def read_device(captures: str, device: str, subtrees=CHECKLIST_SUBTREES) -> list:
    """Every row of one device's capture files that falls under ``subtrees``."""
    rows = []
    for name in CAPTURE_FILES:
        path = os.path.join(captures, f"{device}-{name}.txt")
        if os.path.exists(path):
            rows += [(o, v) for o, v in read_capture(path)
                     if any(o == s or o.startswith(s + ".") for s in subtrees)]
    return rows


def write_fixtures(captures: str, out_dir: str) -> None:
    for device in DEVICES:
        rows = read_device(captures, device)
        path = os.path.join(out_dir, f"checklist_{device}.snmp")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(f"# {device}: rows the configuration checks read, converted from the\n"
                     "# lab capture of 8 Oct 2026 (scripts/captures.py). No serial numbers.\n")
            for oid, value in rows:
                fh.write(f"{oid}\t{value}\n")
        print(f"{path}: {len(rows)} rows")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("captures", help="folder with <device>-<table>.txt captures")
    parser.add_argument("--fixtures", metavar="DIR", required=True,
                        help="write checklist_<device>.snmp fixtures to DIR")
    args = parser.parse_args(argv)
    write_fixtures(os.path.expanduser(args.captures), args.fixtures)
    return 0


if __name__ == "__main__":
    sys.exit(main())
