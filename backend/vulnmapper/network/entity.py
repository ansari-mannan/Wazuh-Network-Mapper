"""Exact model and serial from the standard inventory table (ENTITY-MIB).

``entPhysicalTable`` (1.3.6.1.2.1.47.1.1.1.1) is a standard every vendor may
implement. A system description names only the software image family
("C3750"); this table names the product ("WS-C3750-48TS-S") and carries the
serial number.

Only the columns needed are read, and only their first rows: the table can be
large (about 950 rows on an HP 1920), but the chassis entry comes first or
near it. The cost per device is two requests (one GETBULK page of the class
column, one GET of the chosen entry's serial and model), or three for a device
with no class column (a page of the model column instead).

Which entry is the device:

  * the chassis entry (entPhysicalClass 3) with the lowest index;
  * in a stack every member is a chassis, so this is the first member (the
    stack itself is class 11 and names no product);
  * a table with no class column: the lowest-index entry that has a model
    name.

A device that does not answer the table gives ``{}`` and loses nothing.
"""

from __future__ import annotations

import re
from typing import Optional

ENT_PHYSICAL_ENTRY = "1.3.6.1.2.1.47.1.1.1.1"
COL_CLASS = 5
COL_SERIAL = 11
COL_MODEL = 13
CLASS_CHASSIS = 3

# Rows read from a column: one GETBULK page.
PAGE_ROWS = 50

_CLASS_RE = re.compile(r"(\d+)\)?\s*$")      # "3" or "chassis(3)"


def _column(rows: list, col: int) -> dict:
    """``{index: value}`` for one column's rows."""
    prefix = f"{ENT_PHYSICAL_ENTRY}.{col}."
    out: dict = {}
    for oid, value in rows:
        if oid.startswith(prefix):
            try:
                out[int(oid[len(prefix):])] = value
            except ValueError:
                continue
    return out


def _clean(value) -> Optional[str]:
    text = (value or "").strip()
    return text or None


def choose_chassis(class_rows: list) -> Optional[int]:
    """The index of the device's own entry from entPhysicalClass rows, or None."""
    chassis = []
    for index, value in _column(class_rows, COL_CLASS).items():
        match = _CLASS_RE.search(value or "")
        if match and int(match.group(1)) == CLASS_CHASSIS:
            chassis.append(index)
    return min(chassis) if chassis else None


async def collect_inventory(client, ip: str) -> dict:
    """``{"model", "serial"}`` (each only when the table has it), else ``{}``."""
    page = {"max_repetitions": PAGE_ROWS, "max_rows": PAGE_ROWS}
    index = choose_chassis(
        await client.walk(ip, f"{ENT_PHYSICAL_ENTRY}.{COL_CLASS}", **page))
    if index is None:
        named = {i: v for i, v in _column(
            await client.walk(ip, f"{ENT_PHYSICAL_ENTRY}.{COL_MODEL}", **page),
            COL_MODEL).items() if _clean(v)}
        index = min(named) if named else None
    if index is None:
        return {}
    oids = {f"{ENT_PHYSICAL_ENTRY}.{COL_SERIAL}.{index}": "serial",
            f"{ENT_PHYSICAL_ENTRY}.{COL_MODEL}.{index}": "model"}
    got = await client.get_many(ip, list(oids)) or {}
    return {field: _clean(got.get(oid)) for oid, field in oids.items() if _clean(got.get(oid))}


def merge(specifics: dict, inventory: dict) -> dict:
    """Combine vendor-module fields with the inventory table's.

    The table fills a serial the vendor code did not give and makes the model
    the exact product name, except for fields the vendor module marks as its
    own (``authoritative``), e.g. a FortiGate's model and serial from
    Fortinet's own OIDs.
    """
    own = set(specifics.get("authoritative") or ())
    out = {k: specifics.get(k) for k in ("model", "firmware", "serial")}
    if inventory.get("model") and "model" not in own:
        out["model"] = inventory["model"]
    if inventory.get("serial") and "serial" not in own and not out.get("serial"):
        out["serial"] = inventory["serial"]
    return out
