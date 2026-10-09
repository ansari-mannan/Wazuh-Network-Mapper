#!/usr/bin/env python3
"""Developer helper: label the hosts of an existing graph without rescanning.

The sample graph (data/graph.json) was written before hosts were labelled
managed or unmanaged. This applies what needs only the graph itself
(vulnmapper.hosts.label: unmanaged, mac_type, mac_vendor, metadata.coverage)
and writes the graph back. It is not a scan: no name lookup, no SNMP, nothing
touches the network.

    python3 scripts/hosts_sample_graph.py ../data/graph.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from vulnmapper.hosts import label  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("graph", help="graph.json to update in place")
    args = parser.parse_args(argv)
    with open(args.graph, encoding="utf-8") as fh:
        graph = json.load(fh)
    label(graph)
    with open(args.graph, "w", encoding="utf-8") as fh:
        json.dump(graph, fh, indent=2)
        fh.write("\n")
    for node in graph["nodes"]:
        if node.get("kind") == "endpoint":
            print(f"  {str(node.get('hostname') or node.get('ip') or node['node_id']):<28} "
                  f"{'unmanaged' if node['unmanaged'] else 'managed  '} "
                  f"{node.get('mac_type') or '-':<7} {node.get('mac_vendor') or '-'}")
    print(graph["metadata"]["coverage"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
