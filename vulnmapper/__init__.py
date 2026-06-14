"""vulnmapper — the unified Wazuh-Network-Mapper pipeline.

One package, layered:

  common/    shared node/edge schema, MAC canonicalization, config helpers
  endpoints/ the Wazuh endpoint collector (NTM) and CVE scorer (APA)
  network/   the seed-based SNMP/LLDP infrastructure crawler (+ FDB)
  linking/   endpoint -> switch edge resolution from switch forwarding tables
  assemble/  merge everything into one {nodes, edges, metadata} graph document

The top-level run (``python -m vulnmapper``) chains collect -> score -> link ->
assemble and emits a single unified graph JSON on stdout.
"""

__all__ = ["common", "endpoints", "network", "linking", "assemble"]
