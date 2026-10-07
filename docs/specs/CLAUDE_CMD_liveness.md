# CLAUDE_CMD: Liveness heartbeat (active / inactive nodes)

## Goal

Add a light background check that tells us, every few seconds, whether each node already in `data/graph.json` is still reachable. The result is a `liveness` value per node (`active`, `inactive`, `unknown`) that the plugin UI uses to dim, filter and set aside nodes that have left the network, without waiting for the switch MAC table to age out (about 5 minutes) or for Wazuh to mark an agent disconnected (about 10 minutes).

Motivating case: a phone joins Wi-Fi and is found by a scan as an `snmp_fdb` host. It leaves, and the next scan still shows it. With this feature it must go `inactive` within about a minute and move out of the topology canvas.

## Hard rules

1. Work on a new branch `liveness` created from `main`. Commit after each phase. Do not merge into `main`. Push only when I say.
2. Do not change `backend/vulnmapper/assemble.py`, `backend/vulnmapper/pipeline.py`, the scan output format, or anything under `frontend/` (old standalone GUI). The 90 existing tests and the golden test must stay green without re-freezing.
3. The liveness pass never writes `graph.json`. It only reads it. Its results live in a separate `liveness.json`. (Two writers on one file would race with a scan, and reloading the graph every few seconds would re-run the layout.)
4. Probe only IPs that are already in `graph.json`. No sweeps, no subnet scans, no new discovery. This keeps the two-source rule: SNMP/LLDP discovers network devices, Wazuh discovers endpoints, liveness only re-checks what they found.
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

Entry point: `python -m vulnmapper.liveness --graph PATH [--state PATH] [--threshold 3]`

- Reads the graph at `--graph` and the previous state at `--state` (missing or invalid file = empty state).
- Runs one pass and prints the new state document as JSON on stdout. Logs go to stderr only, same contract as `pipeline.py`.
- Always exits 0 with a valid document unless the graph itself cannot be read.

### Probe method per node

| Node | Method |
|---|---|
| `kind == "device"`, `pollable` true, has `ip`, SNMP credentials available | `snmp`: reuse `SnmpClient` and `load_credentials(None)`; a successful credential resolve / sysUpTime GET is a reply. Timeout 1 s, 1 retry. |
| same device, no SNMP credentials available | `icmp` |
| `kind == "endpoint"` with `ip` (Wazuh agents and `snmp_fdb` hosts) | `icmp`: `ping -c 1 -W 1 <ip>`, exit code 0 is a reply |
| no `ip` | no probe |

Run probes concurrently with a cap of 32 in flight. One pass over the current lab graph should finish in under 5 seconds.

Shared IPs: if two or more nodes have the same IP, skip nodes with `stale: true`. If more than one node still shares the IP, do not probe them; they stay `unknown` with `reason: "shared_ip"`.

### State rules (per node)

Stored fields: `state`, `method`, `last_seen`, `last_checked`, `misses`, `proven_methods`, optional `reason`, optional `port_down` (`{device, port, previous_state}`, see Phase 4).

- Reply via method M: `state = "active"`, `misses = 0`, `last_seen = now`, add M to `proven_methods`.
- No reply via method M, and M is in `proven_methods`: `misses += 1`. When `misses >= threshold`, `state = "inactive"`. Below the threshold the state does not change.
- No reply via method M, and M is NOT in `proven_methods`: silence proves nothing (Windows blocks ping by default). `misses` unchanged. State stays as it was, or `"unknown"` if the node has no state yet.
- No probe possible: `state = "unknown"`, `method = null`.
- Nodes no longer in the graph are dropped from the state. `proven_methods` and `last_seen` survive across passes and across scans for nodes that remain.

### Output shape

```json
{
  "checked_at": "2026-10-07T09:15:02+00:00",
  "threshold": 3,
  "nodes": {
    "host:54:75:d0:ab:bd:1a": {
      "state": "inactive", "method": "icmp", "misses": 3,
      "last_seen": "2026-10-07T09:13:41+00:00",
      "last_checked": "2026-10-07T09:15:02+00:00",
      "proven_methods": ["icmp"]
    }
  }
}
```

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
   - `liveness.intervalSeconds` (number, default `20`, min `10`)
   - `liveness.missThreshold` (number, default `3`, min `1`)
   - `liveness.path` (optional string; default is `liveness.json` in the same folder as `graphPath`)
2. `plugin/server/scan.ts`: keep the last community that was passed to `startScan` in module memory and export a getter. Memory only.
3. New `plugin/server/liveness.ts`:
   - A timer started from `VulnmapperPlugin.start()` and cleared in `stop()`, only when `liveness.enabled` is true and `backendDir` / `graphPath` are set.
   - Each tick is skipped if the previous pass is still running, if a scan is running (`getScan().status === 'running'`), or if the graph file does not exist.
   - Spawns `<pythonBin> -m vulnmapper.liveness --graph <graphPath> --state <livenessPath> --threshold <n>` in `backendDir`. Community goes through `SNMP_COMMUNITIES` in the child env when known.
   - Kills the child if it runs longer than the interval.
   - Validates stdout as JSON, writes to a temp file, renames over `livenessPath` (same pattern as the scan).
   - Logs one line at `debug` per pass and `warn` on failure. No per-node logging at `info`.
4. `plugin/server/routes/index.ts`: add `GET /api/vulnmapper/liveness` returning `{ enabled, intervalSeconds, checkedAt, nodes }`. When disabled or no file yet: `{ enabled: <bool>, intervalSeconds, checkedAt: null, nodes: {} }`. The existing graph and scan routes stay as they are.

## Phase 3: plugin UI

1. `plugin/common/types.ts`: add `LivenessState`, `NodeLiveness`, `LivenessResponse`.
2. New `plugin/public/lib/liveness.tsx`: a provider that polls the route every `intervalSeconds` while enabled and the browser tab is visible. It must not call the graph `reload` and must not trigger a re-layout on its own.
3. Node look (`nodeStyle.ts`, `CustomNode.tsx`):
   - `inactive`: dimmed + dashed, same look `isOffline` gives today.
   - `active`: not dimmed, even when `status` is `discovered` (today every `snmp_fdb` host looks offline because `isOffline` treats `discovered` as offline).
   - `unknown` or no liveness data: exactly today's behaviour.
4. `DeviceDetail.tsx`: a "Liveness" row with the state badge, last seen time, and method.
5. `TopologyPage.tsx` toolbar: an `EuiSwitch` "Hide inactive discovered hosts", default on.
   - When on, nodes that are `inactive` AND `kind == "endpoint"` AND `discovery_method == "snmp_fdb"` are removed from the canvas (with their edges) and listed in a compact side panel "Inactive (n)" showing IP, MAC and last seen.
   - Inactive Wazuh agents (`discovery_method == "wazuh"`) and inactive network devices always stay on the canvas, dimmed.
   - Re-layout only when the set of hidden nodes changes, not on every poll.
6. When liveness is disabled, the switch and side panel are not rendered and the UI is identical to today.
7. Use EUI components and the existing theme tokens so dark and light modes both work.

## Phase 4 (required): port-down layer

For each pollable device that answered SNMP in the pass, call the existing `collect_port_status` unchanged. If an endpoint's `endpoint_link` edge points at that device with a `local_port` that is now `down`, mark the endpoint `inactive` immediately with `method: "port"` (unless it answered a probe in the same pass), and store `port_down: {device, port, previous_state}`, where `previous_state` is the state it had before the port went down (null if it had none). While `port_down` stands, a probe with no reply changes nothing (the down port explains the silence).

Port recovery: on a later pass, restore `previous_state` (or `"unknown"` if null), reset `misses` to 0, keep `proven_methods` and drop `port_down`, when either the same port is reported `up` again, or the node's `endpoint_link` in the graph no longer points at that device and port (a new scan placed it elsewhere). If the new place is also down, the node is marked again. If the device does not answer SNMP in a pass, its ports are unknown and nothing changes. A reply to any probe still makes the node `active` and drops `port_down`. A port that is `up` never makes a node `active` by itself. Add tests. Skip this phase if `collect_port_status` cannot be reused without edits, and tell me why.

## Verification

Offline (always):
- `python -m unittest discover -s tests` -> the 90 old tests plus the new ones all pass; golden unchanged.
- The plugin type-checks and the zip builds with the command in `plugin/README.md`.
- With `liveness.enabled: false` the plugin behaves exactly as before.

Live (lab, mark pending if not reachable). Set in the dashboard config: `vulnmapper.liveness.enabled: true`.
1. Join a phone to Wi-Fi, run a scan. The phone node appears and turns `active` within one interval.
2. Turn the phone's Wi-Fi off. Within about `missThreshold x intervalSeconds` (plus one interval) it becomes `inactive` and moves to the "Inactive" panel, with no new scan.
3. Turn Wi-Fi back on. It returns to the canvas as `active` on the next pass.
4. A Windows PC that blocks ping stays `unknown` and looks as it does today.
5. A disconnected Wazuh agent stays on the canvas.
6. `graph.json` modification time does not change while only liveness passes run.

## Out of scope

SNMP traps or any device-side config, ping sweeps, changes to scan logic or `graph.json` contents, the overview page, a UI control for the interval (config file only for now), the old `frontend/` app.

## Report back

For each phase: files changed, test counts, the Phase 0 outputs, and anything you had to decide that this spec did not cover. Update `plugin/README.md` and `backend/README.md` with the new config keys and the `python -m vulnmapper.liveness` command, in a few lines each.
