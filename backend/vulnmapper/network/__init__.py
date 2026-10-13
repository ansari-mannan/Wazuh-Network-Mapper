"""The network side of a scan: a crawl outward from a seed over LLDP and CDP
neighbour tables (crawl.py), reading each switch's, router's and access
point's identity, forwarding table, ARP table and port states over SNMP. Hosts
come from the Wazuh side and from these tables, during assembly.
"""
