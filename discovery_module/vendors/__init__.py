"""Vendor identification plug-ins.

Each vendor module exposes::

    async def identify(sys_descr, sys_object_id, snmp_client, ip) -> dict

returning the device-specific fields (model, firmware, serial). To add a new
vendor, drop in a module with an ``identify`` coroutine and register its
enterprise number in :data:`VENDOR_BY_ENTERPRISE`.
"""

from . import cisco, fortinet

# Enterprise number (the arc after 1.3.6.1.4.1.) -> (vendor name, module).
VENDOR_BY_ENTERPRISE = {
    "9": ("Cisco", cisco),
    "12356": ("Fortinet", fortinet),
}

__all__ = ["VENDOR_BY_ENTERPRISE", "cisco", "fortinet"]
