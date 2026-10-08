# CLAUDE_CMD: Liveness heartbeat (active / inactive nodes)

## Goal

Add a light background check that tells us, every few seconds, whether each node already in `data/graph.json` is still reachable. The result is a `liveness` value per node (`active`, `inactive`, `unknown`) that the plugin UI uses to dim, filter and set aside nodes that have left the network, without waiting for the switch MAC table to age out (about 5 minutes) or for Wazuh to mark an agent disconnected (about 10 minutes).

Motivating case: a phone joins Wi-Fi and is found by a scan as an `snmp_fdb` host. It leaves, and the next scan still shows it. With this feature it must go `inactive` within about a minute and move out of the topology canvas.

This spec has been revised for the second round of work (Wazuh agent check-in, faster defaults, automatic rescan, every inactive host in the side panel); see "Second round" at the end. Where the two differ, the revised text below is current.

## Hard rules

1. Work on a new branch `liveness` created from `main`. Commit after each phase. Do not merge into `main`. Push only when I say.
2. Do not change `backend/vulnmapper/assemble.py`, `backend/vulnmapper/pipeline.py`, the scan output format, or anything under `frontend/` (old standalone GUI). The 90 existing tests and the golden test must stay green without re-freezing.
3. The liveness pass never writes `graph.json`. It only reads it. Its results live in a separate `liveness.json`. (Two writers on one file would race with a scan, and reloading the graph every few seconds would re-run the layout.)
4. Probe only IPs that are already in `graph.json`. No sweeps, no subnet scans, no new discovery. This keeps the two-source rule: SNMP/LLDP discovers network devices, Wazuh discovers endpoints, liveness only re-checks what they found. (A pass may *suggest* a rescan when something new appears; the scan itself does the discovery. See Phase 5.)
5. Nothing is installed or configured on the switches, firewall or Wazuh server.
6. No new Python dependencies. ICMP uses the system `ping` binary through `asyncio.create_subprocess_exec` with an argv list (never a shell string). Validate every IP with `ipaddress.ip_address` before it reaches argv.
7. The SNMP community is never logged, never written to disk, never placed in argv. Same handling as `plugin/server/scan.ts`.
8. Test first: write failing tests, then the code. HALT and report if a Phase 0 gate fails.

## Phase 0: gates (before any code)

Run and record the output in your report:

1. `cd backend && python -m unittest discover -s tests` -> 90 tests OK. HALT if not.
2. `ping -c 1 -W 1 127.0.0.1` exits 0 as the normal user (no sudo). HALT if not.
3. Lab check, only if `ping -c 1 -W 1 172.20.40.254` succeeds:
   - For every node IP in `data/graph.json`, record whether it answers one ping. I need this list to know which hosts are pingable.
   - If `SNMP_COMMUNITIES` is set in the environment, confirm the three pollable devices (L3-Switch, CYFOR-Firewall, CYFOR-HP-Switch) answer an SNMP GET of sysUpTime `1.3.6.1.2.1.1.3.0` through the existing `SnmpClient`. If it is not set, ask me to export it; do not put it in any file.
   - If the lab is not reachable, say so, continue with the offline phases, and mark live verification as pending.

## Phase 1: backend module `backend/vulnmapper/liveness.py`

Entry point: `python -m vulnmapper.liveness --graph PATH [--state PATH] [--threshold 2] [--agent-max-age 30]`

- Reads the graph at `--graph` and the previous state at `--state` (missing or invalid file = empty state).
- Runs one pass and prints the new state document as JSON on stdout. Logs go to stderr only, same contract as `pipeline.py`.
- Always exits 0 with a valid document unless the graph itself cannot be read.

### Probe method per node

| Node | Method |
|---|---|
| `kind == "endpoint"` with an `agent_id`, Wazuh credentials (`WAZUH_PASS`) available | `agent`: see "Wazuh agent check-in" below. Matched by agent id, so a missing or shared IP does not matter. Not pinged. |
| `kind == "device"`, `pollable` true, has `ip`, SNMP credentials available | `snmp`: reuse `SnmpClient` and `load_credentials(None)`; a successful credential resolve / sysUpTime GET is a reply. Timeout 1 s, 1 retry. |
| same device, no SNMP credentials available | `icmp` |
| endpoint linked to an access point with confidence `wifi` (no agent method), the AP pollable and SNMP credentials available | `wifi`: in the AP's client list this pass is a reply (see Phase 6). Not pinged. |
| `kind == "endpoint"` with `ip` (`snmp_fdb` hosts, and Wazuh agents when no Wazuh credentials are set) | `icmp`: `ping -c 1 -W 1 <ip>`, exit code 0 is a reply; then `mac-table` if no faster method was ever proven (Phase 6) |
| no `ip` | no probe |

Run probes concurrently with a cap of 32 in flight. One pass over the current lab graph should finish in under 5 seconds.

### Wazuh agent check-in (method `agent`)

Windows PCs do not answer ping, but every agent checks in with the manager. Once per pass, log in to the Manager API with the existing Wazuh configuration and login code (`WazuhSource`, read-only helper `agent_status()`) and fetch `id`, `status` and `lastKeepAlive` for all agents in one request (paged if needed).

- `status == "active"` and `lastKeepAlive` within `--agent-max-age` seconds of now (default 30; lab check-ins were a few seconds old): a reply, except on a down port (Phase 4).
- `status == "active"` with an older check-in: a miss under the normal threshold. `agent` is a proven method from the start, so this counts even before any reply.
- `disconnected`, `pending` or `never_connected`: `inactive` at once.
- Agent `000` is the manager itself and reports a far-future `lastKeepAlive`: a reply.
- An agent the manager does not list: unchanged, `reason: "agent_not_listed"`.
- Time box: if the login or request fails or takes longer than 5 s, the method is skipped for the pass; those nodes keep their state with `reason: "agent_unavailable"` and the document carries `agent_error`. The requests run in a daemon thread so they cannot hold up the pass.
- No Wazuh credentials in the environment: today's behaviour (ping).
- The port layer (Phase 4) still applies to these endpoints. The node record keeps the last known `agent: {status, last_keepalive}`.

Shared IPs: if two or more nodes have the same IP, skip nodes with `stale: true`. If more than one node still shares the IP, do not probe them; they stay `unknown` with `reason: "shared_ip"`.

### State rules (per node)

Stored fields: `state`, `method`, `last_seen`, `last_checked`, `misses`, `proven_methods`, optional `reason`, optional `port_down` (`{device, port, previous_state, since}`, see Phase 4).

- Reply via method M: `state = "active"`, `misses = 0`, `last_seen = now`, add M to `proven_methods`.
- No reply via method M, and M is in `proven_methods` (or M is `agent`): `misses += 1`. When `misses >= threshold`, `state = "inactive"`. Below the threshold the state does not change.
- No reply via method M, and M is NOT in `proven_methods`: silence proves nothing (Windows blocks ping by default). `misses` unchanged. State stays as it was, or `"unknown"` if the node has no state yet.
- The agent reports `disconnected`, `pending` or `never_connected`: `misses += 1`, `state = "inactive"` at once.
- No probe possible: `state = "unknown"`, `method = null`.
- Nodes no longer in the graph are dropped from the state. `proven_methods` and `last_seen` survive across passes and across scans for nodes that remain.

### Output shape

```json
{
  "checked_at": "2026-10-07T09:15:02+00:00",
  "threshold": 2,
  "nodes": {
    "host:54:75:d0:ab:bd:1a": {
      "state": "inactive", "method": "icmp", "misses": 2,
      "last_seen": "2026-10-07T09:13:41+00:00",
      "last_checked": "2026-10-07T09:15:02+00:00",
      "proven_methods": ["icmp"]
    },
    "endpoint:001": {
      "state": "active", "method": "agent", "misses": 0,
      "last_seen": "2026-10-07T09:15:02+00:00",
      "last_checked": "2026-10-07T09:15:02+00:00",
      "proven_methods": ["agent"],
      "agent": {"status": "active", "last_keepalive": "2026-10-07T09:14:54+00:00"}
    }
  },
  "ports": {"device:00:23:ac:e5:74:00": {"Fa1/0/15": "up", "Fa1/0/20": "up"}},
  "graph_scan_time": "2026-10-07T11:33:19.844771+00:00",
  "rescan_suggested": true,
  "rescan_reasons": ["port Fa1/0/20 on L3-Switch came up with nothing linked to it"]
}
```

`agent_error` is present only when the agent method was skipped for the pass.

### Tests: `backend/tests/test_liveness.py` (fixtures only, no network)

Inject fake probers so nothing touches the network. Cover at least:

- reply -> active, misses reset, method recorded as proven
- proven method, 2 misses -> still active; 3rd miss -> inactive
- never-proven method, any number of misses -> stays unknown
- inactive node replies again -> active
- device proven by `snmp`, later probed by `icmp` with no reply -> not marked inactive
- node without IP -> unknown, no probe attempted
- shared IP: stale node skipped; two non-stale nodes -> both unknown with `shared_ip`
- node removed from graph -> removed from state
- invalid IP string in the graph -> not probed, no exception
- corrupt or missing state file -> treated as empty

## Phase 2: plugin server

1. `plugin/server/config.ts`: add
   - `liveness.enabled` (boolean, default `false`)
   - `liveness.intervalSeconds` (number, default `10`, min `10`)
   - `liveness.missThreshold` (number, default `2`, min `1`)
   - `liveness.agentMaxAgeSeconds` (number, default `30`, min `10`; passed as `--agent-max-age`)
   - `liveness.autoRescan` (boolean, default `true`; Phase 5)
   - `liveness.minRescanIntervalSeconds` (number, default `120`, min `60`; Phase 5)
   - `liveness.path` (optional string; default is `liveness.json` in the same folder as `graphPath`)
2. `plugin/server/scan.ts`: keep the last community that was passed to `startScan` in module memory and export a getter. Memory only.
3. New `plugin/server/liveness.ts`:
   - A timer started from `VulnmapperPlugin.start()` and cleared in `stop()`, only when `liveness.enabled` is true and `backendDir` / `graphPath` are set.
   - Each tick is skipped if the previous pass is still running, if a scan is running (`getScan().status === 'running'`), or if the graph file does not exist.
   - Spawns `<pythonBin> -m vulnmapper.liveness --graph <graphPath> --state <livenessPath> --threshold <n> --agent-max-age <s>` in `backendDir`. Community goes through `SNMP_COMMUNITIES` in the child env when known; `WAZUH_PASS` comes from the server's own environment, as for a scan.
   - Kills the child if it runs longer than the interval.
   - Validates stdout as JSON, writes to a temp file, renames over `livenessPath` (same pattern as the scan).
   - Logs one line at `debug` per pass and `warn` on failure. No per-node logging at `info`.
4. `plugin/server/routes/index.ts`: add `GET /api/vulnmapper/liveness` returning `{ enabled, intervalSeconds, checkedAt, nodes, graphMtime }`. When disabled or no file yet: `{ enabled: <bool>, intervalSeconds, checkedAt: null, nodes: {}, graphMtime }`. `graphMtime` is the graph file's modified time (ISO, null if there is no file). The existing graph and scan routes stay as they are.

## Phase 3: plugin UI

1. `plugin/common/types.ts`: add `LivenessState`, `NodeLiveness`, `LivenessResponse`.
2. New `plugin/public/lib/liveness.tsx`: a provider that polls the route every `intervalSeconds` while enabled and the browser tab is visible. Liveness changes alone must not call the graph `reload` or trigger a re-layout; the graph is reloaded only when `graphMtime` changes (an automatic scan wrote a new graph), once per new value.
3. Node look (`nodeStyle.ts`, `CustomNode.tsx`):
   - `inactive`: dimmed + dashed, same look `isOffline` gives today.
   - `active`: not dimmed, even when `status` is `discovered` (today every `snmp_fdb` host looks offline because `isOffline` treats `discovered` as offline).
   - `unknown` or no liveness data: exactly today's behaviour.
4. `DeviceDetail.tsx`: a "Liveness" row with the state badge, last seen time, and the method in words (for example "via Wazuh agent check-in, 8 s ago", "via Wazuh agent disconnected, last check-in 3 h ago", "via ping").
5. `TopologyPage.tsx` toolbar: an `EuiSwitch` "Hide inactive hosts", default on.
   - When on, every node that is `inactive` AND `kind == "endpoint"`, whatever its discovery method, is removed from the canvas (with its edges) and listed in a compact side panel "Inactive (n)" showing name or IP, MAC, last seen and the method; an entry opens the flyout.
   - Nodes of kind `device` never leave the canvas; inactive ones stay dimmed, because removing a switch would orphan what hangs off it.
   - Re-layout only when the set of hidden nodes changes, not on every poll.
6. When liveness is disabled, the switch and side panel are not rendered and the UI is identical to today.
7. Use EUI components and the existing theme tokens so dark and light modes both work.

## Phase 4 (required): port-down layer

For each pollable device that answered SNMP in the pass, call the existing `collect_port_status` unchanged. If an endpoint's `endpoint_link` edge points at that device with a `local_port` that is now `down`, mark the endpoint `inactive` immediately with `method: "port"`, and store `port_down: {device, port, previous_state, since}`, where `previous_state` is the state it had before the port went down (null if it had none) and `since` is the time the port was first observed down (kept while it stays down). While `port_down` stands, a probe with no reply changes nothing (the down port explains the silence).

A ping or SNMP reply in the same pass still overrides a down port. An agent check-in does not by itself: `lastKeepAlive` is a stored time, not a live reply. On a down port (or one already marked down whose switch did not answer this pass) the agent counts as a reply only if `lastKeepAlive` is later than `since`; otherwise the down port wins and the agent method neither replies nor misses. A state file written before `since` existed is treated strictly: the port counts as first observed down in the current pass.

Port recovery: on a later pass, restore `previous_state` (or `"unknown"` if null), reset `misses` to 0, keep `proven_methods` and drop `port_down`, when either the same port is reported `up` again, or the node's `endpoint_link` in the graph no longer points at that device and port (a new scan placed it elsewhere). If the new place is also down, the node is marked again. If the device does not answer SNMP in a pass, its ports are unknown and nothing changes. A reply to any probe still makes the node `active` and drops `port_down`; for the agent method that means a check-in later than `since`, since the machine has reconnected some other way. A port that is `up` never makes a node `active` by itself. Add tests. Skip this phase if `collect_port_status` cannot be reused without edits, and tell me why.

## Phase 5: automatic rescan

The heartbeat only re-checks nodes it already knows, so a newly connected device would not appear until someone ran a scan.

- Backend: the port status of every SNMP-answering pollable device is read and remembered between passes (`ports`; a device that does not answer keeps what it had). A pass suggests a rescan when (a) a port goes from down to up and no graph edge uses that port (a host link's switch port, or either end of a device link), or (b) the Manager API lists an active agent, other than 000, that is not in the graph. A port coming back up for a node the graph already links there is recovery, not a reason. The document carries `rescan_suggested` and a short list (at most 10) of `rescan_reasons`; the suggestion stands until a new scan replaces the graph (`graph_scan_time`, from `metadata.scan_time`), so it is not lost while a scan runs or the plugin waits.
- Plugin server (`autoRescan.ts`): after a pass that suggests a rescan, when `liveness.autoRescan` is on, start a scan through the same `startScan` path as a manual scan, with the last community given to a scan. Never while a scan runs, and never sooner than `liveness.minRescanIntervalSeconds` after the last scan started, automatic or manual.
- UI: reloads the graph when `graphMtime` changes, so an automatic scan's result appears without a manual reload.

## Phase 6: access points and the MAC table

- `wifi`: once per pass, every access point (role `access-point`) that answered SNMP has its client list read (one column walk of cDot11ClientConfigInfoTable; an empty list counts only when the AP's per-radio client counters say it is empty). A node linked to it with confidence `wifi` replied if its MAC is in the list; an agent endpoint keeps its agent method as well. Missing from the list is handled exactly like a down port: inactive at once with method `wifi`, `port_down: {device: <AP>, port: "wifi", previous_state, since}`, revived by a Wazuh check-in later than `since` or by reappearing in the list. If the AP does not answer, nothing changes (`reason: "wifi_unavailable"`). The port layer works per link, so a Wi-Fi link is never judged by the radio interface's status. A MAC in a client list that is not in the graph is a rescan reason.
- `mac-table`: a wired endpoint with a MAC and a known switch port (on a switch that answered SNMP this pass), no agent, not marked down by its port, and no method in `icmp`, `snmp`, `agent`, `wifi` ever proven, is looked up in its switch's forwarding table: found on that port is a reply, not found (or on another port) a miss under the normal threshold, counting from the start. Specific entries are fetched with GETs (Cisco: 802.1D in the community@vlan context, using the `vlan` the scan records on the node; others: 802.1Q in the default context), one batched lookup per switch per pass, then bridge port -> ifIndex -> ifName. A switch that does not answer within 2 s is skipped for the pass (`reason: "mac_table_unavailable"`). A MAC-table entry is not a live reply: a down port still wins.

## Verification

Offline (always):
- `python -m unittest discover -s tests` -> the 90 old tests plus the new ones all pass; golden unchanged.
- The plugin type-checks and the zip builds with the command in `plugin/README.md`.
- With `liveness.enabled: false` the plugin behaves exactly as before.

Live (lab, mark pending if not reachable). Set in the dashboard config: `vulnmapper.liveness.enabled: true`.
1. Join a phone to Wi-Fi, run a scan. The phone node appears and turns `active` within one interval.
2. Turn the phone's Wi-Fi off. Within about `missThreshold x intervalSeconds` (plus one interval) it becomes `inactive` and moves to the "Inactive" panel, with no new scan.
3. Turn Wi-Fi back on. It returns to the canvas as `active` on the next pass.
4. With `WAZUH_PASS` set, a Windows PC that blocks ping shows "via Wazuh agent check-in, N s ago" and is `active`; stopping its agent makes it `inactive` once the manager marks it disconnected, or after `missThreshold` stale check-ins.
5. A disconnected Wazuh agent moves to the "Inactive" panel; an inactive switch stays on the canvas, dimmed.
6. `graph.json` modification time does not change while only liveness passes run and nothing new appears.
7. Plug a new device into an empty switch port: within a pass or two a scan starts by itself (at most one per `minRescanIntervalSeconds`) and the device appears on the map without a manual reload.

## Out of scope

SNMP traps or any device-side config, ping sweeps, changes to scan logic or `graph.json` contents, the overview page, a UI control for the interval (config file only for now), the old `frontend/` app.

## Report back

For each phase: files changed, test counts, the Phase 0 outputs, and anything you had to decide that this spec did not cover. Update `plugin/README.md` and `backend/README.md` with the new config keys and the `python -m vulnmapper.liveness` command, in a few lines each.

## Second round (7 Oct)

Changes made after the first version, and where they override the text above:

1. Assembler (outside liveness): the subnet fallback (`subnet_fallback`) now applies only to endpoints whose Wazuh status is `active`; any other endpoint with no table or LLDP evidence stays unparented (`host_offline_no_l2_evidence`). This was the one permitted change to `assemble.py`; the golden expectation was updated for it.
2. Map (outside liveness): a device-to-device link shows both ports, each next to the device it belongs to, whichever way the link was recorded; a host link keeps the switch port in the middle.
3. Every inactive endpoint, not only `snmp_fdb` hosts, leaves the canvas for the "Inactive (n)" panel; devices never do. The switch is "Hide inactive hosts".
4. Wazuh agent check-in is a liveness method (`agent`), with `liveness.agentMaxAgeSeconds`.
5. Faster defaults: `intervalSeconds` 10, `missThreshold` 2 (CLI `--threshold` default 2).
6. Automatic rescan (Phase 5), with `liveness.autoRescan` and `liveness.minRescanIntervalSeconds`, and `graphMtime` on the liveness route.
