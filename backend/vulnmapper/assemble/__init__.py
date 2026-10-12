"""Assembly: the Wazuh endpoints and the crawl's network document become one
``{nodes, edges, metadata}`` graph (``graph.py``), using the MAC lookup table
built from the switches' forwarding and ARP tables (``mactable.py``).
"""

from .graph import GraphAssembler, assemble

__all__ = ["GraphAssembler", "assemble"]
