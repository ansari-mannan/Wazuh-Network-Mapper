"""Liveness heartbeat: re-check whether the nodes already in graph.json answer.

    python -m vulnmapper.liveness --graph PATH [--state PATH] [--threshold 2]
                                  [--agent-max-age 30]

Reads the graph (never writes it) and the previous state, runs one pass and
prints the new state document on stdout; logs go to stderr only, the same
contract as ``pipeline.py``. Exits 0 with a valid document unless the graph
itself cannot be read.

Only IPs already in the graph are probed: no sweeps, no discovery.

Probe method per node
  * endpoint with an ``agent_id``, Wazuh credentials available -> ``agent``:
    one Manager API request per pass lists every agent's status and
    lastKeepAlive. Active with a check-in no older than ``--agent-max-age``
    seconds is a reply (agent 000, the manager, always is); active with an
    older check-in is a miss; disconnected / pending / never_connected makes
    the node inactive at once. If the login or request fails or takes longer
    than 5 s, these nodes are left as they were for the pass.
  * pollable device with an IP, SNMP credentials available -> ``snmp``
    (a credential that resolves is a reply; a failure is "snmp, no reply")
  * any other node with an IP (endpoints, devices without credentials or not
    pollable) -> ``icmp``: ``ping -c 1 -W 1 <ip>``, exit 0 is a reply
  * no IP, an invalid IP, or an IP shared by more than one non-stale node -> no
    probe (state ``unknown``, method null)

State rules per node: a reply makes it ``active`` (misses 0, ``last_seen`` now,
method proven). Silence on a proven method adds a miss and, at ``threshold``
misses, makes it ``inactive``; below that the state is unchanged. Silence on a
never-proven method proves nothing (Windows blocks ping), so nothing changes;
``agent`` counts as proven from the start (a stale check-in is real evidence).

Port layer: each pollable device that answered SNMP in this pass has its port
status read with the crawler's ``collect_port_status``. An endpoint whose link
to that device uses a port that is now ``down`` becomes ``inactive`` at once
with method ``port``, and ``port_down.since`` records when that port was first
seen down. A ping or SNMP reply in the same pass still wins. An agent check-in
is a stored time, not a live reply: on a down port it counts only if
``lastKeepAlive`` is later than ``since`` (the machine reconnected some other
way). The node gets its earlier state back once the port is up again or a new
scan places it elsewhere. An ``up`` port never makes a node active by itself.

Rescan suggestion: the port states are remembered between passes (``ports``).
A pass sets ``rescan_suggested`` (with short ``rescan_reasons``) when a port
went from down to up and no graph edge uses that port, or when the Manager
API lists an active agent (other than 000) that is not in the graph. A port
coming back up for a node already linked there is recovery, not a reason. The
suggestion stands until a new scan replaces the graph (``graph_scan_time``).
"""

from .cli import load_state, main
from .monitor import liveness_pass
from .prober import SystemProber

__all__ = ["SystemProber", "liveness_pass", "load_state", "main"]
