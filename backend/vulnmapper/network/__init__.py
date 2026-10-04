"""Seed-based SNMP/LLDP infrastructure crawler (routers/switches only).

Crawls LLDP neighbor tables outward from a seed, polling each device's identity
and — new in the unified pipeline — its MAC forwarding table (FDB) and uplink
ports, which the endpoint linker needs to resolve which switch/port each
endpoint hangs off. Endpoints themselves are out of scope here; they come from
the Wazuh side. See :mod:`vulnmapper.network.runner` for the programmatic entry
point and ``python -m vulnmapper.network`` for the CLI.
"""
