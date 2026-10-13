# vulnmapper: Network Topology Mapper plugin

An OpenSearch Dashboards plugin that shows the network topology graph produced
by the Python scanner in `../backend`. It appears in the dashboard's left menu
as **Network Topology Mapper** and has:

- **Overview**: network devices by type, endpoints by status, endpoints and
  devices by risk level, failed device configuration checks by severity, how
  many hosts have a Wazuh agent, and cards for every page.
- **Topology map**: the graph, with draggable nodes, reload and reset, and a
  detail flyout for each device or endpoint. A link between two devices shows
  each device's port next to that device; a host link shows the switch port.
- **Scan settings**: run a scan with an SNMP community string (and,
  optionally, three active checks that are off by default), follow its
  status, and see where the current graph came from.
- **Vulnerability report**: a ranked, exportable report of the CVEs and
  configuration findings per asset (see below).
- **Recommendations**: a network-wide, prioritised and trackable action plan
  (see below).
- Attack paths.

The server side reads the graph file and runs the scanner; the scanner itself
is unchanged.

## Compatibility

| Component | Version |
|---|---|
| OpenSearch Dashboards | 2.19.3 |
| Wazuh dashboard | 4.14.0 / 4.14.1 (based on OpenSearch Dashboards 2.19.3) |
| React / React DOM | 16.14 (from the dashboard) |
| react-router-dom | 5.3 (from the dashboard) |
| OUI (`@elastic/eui`) | 1.19.0 (from the dashboard) |
| TypeScript | 4.0 (from the dashboard) |
| Node.js | 18.19.0 |

Packages added by the plugin, pinned in `package.json`:

| Package | Version | Note |
|---|---|---|
| react-flow-renderer | 10.3.17 | React 16 release of React Flow |
| @dagrejs/dagre | 2.0.4 | graph layout |
| lucide-react | 0.303.0 | newest release whose typings parse under TypeScript 4.0 |
| @types/d3-dispatch | 3.0.1 | resolution: typings for TypeScript 4.0 |
| @types/d3-selection | 3.0.3 | resolution: typings for TypeScript 4.0 |

## Configuration

Set these in `opensearch_dashboards.yml` (or the dev config below):

| Key | Meaning |
|---|---|
| `vulnmapper.backendDir` | folder containing the scanner (`python -m vulnmapper` runs there) |
| `vulnmapper.graphPath` | graph JSON the scanner output is written to and the UI reads |
| `vulnmapper.pythonBin` | Python interpreter for the scanner (default `python3`) |
| `vulnmapper.deviceCves` | look network devices' software up in NVD during a scan (default `true`; `false` starts scans with `--no-device-cves`) |
| `vulnmapper.checkDefaultCommunities` | where the Scan settings switch "Also test factory-default SNMP names (public, private)" starts (default `false`); the switch's position is what a scan uses |
| `vulnmapper.checkManagementPorts` | where the switch "Test whether telnet and web management answer on devices that do not report it" starts (default `false`); on, the scan runs with `--check-management-ports` |
| `vulnmapper.probeUnmanagedSnmp` | where the switch "Ask unmanaged hosts for their identity over SNMP" starts (default `false`); on, the scan runs with `--probe-unmanaged-snmp` |
| `vulnmapper.nmapUnmanaged` | where the switch "Service-scan unmanaged hosts with nmap" starts (default `false`); on, the scan runs with `--nmap-unmanaged`, which actively probes the discovered unmanaged hosts (nmap must be installed) |
| `vulnmapper.reportOrg` | the organisation/owner name shown on the vulnerability report's cover (default `Network Vulnerability Assessment`) |

`backendDir` and `graphPath` have no default; until they are set, the API
returns an error saying which key is missing.

An NVD API key is optional: set `NVD_API_KEY` in the dashboard server's
environment (like `WAZUH_PASS`) and scans pass it on to the scanner through the
environment, never on the command line.

## Device CVEs

Switches, firewalls and access points get their CVEs from NVD by software
version (see "Device CVEs" in `../backend/README.md`). In the detail flyout a
device shows, like a host, its risk summary and its Vulnerabilities, plus a
Software row with the product it was matched as and one line saying what the
findings rest on, e.g. "Potential: matched by software version (Cisco IOS
12.2(55)SE12) against NVD on 9 Oct 2026. A version match does not confirm the
affected feature is in use." A device that is Unscored says why in one
sentence: its software could not be identified, it was never polled, NVD
could not be reached, NVD does not list its version, or (for a product with no
exact identifier) no NVD entry names it. A result served from an old cached
answer because NVD could not be reached is marked stale.

One risk rule drives the node border, the flyout and the overview: a device
with a successful lookup shows its score, a real 0.0 included; anything else
is Unscored. A graph written before device lookups behaves as before (a device
is Unscored unless it carries CVE data). The overview's "Risk level" panel
counts endpoints and devices together.

## Configuration checks

Each polled device is checked against a short list of configuration rules
over SNMP (see "Configuration checks" in `../backend/README.md`). The detail
flyout shows a **Configuration checks** section below the vulnerabilities:

- a summary line, e.g. "5 of 8 checks failed (3 medium, 2 advisory); 2
  unknown, 1 not checked.";
- each failed check: its title, a severity badge (the severity the publishing
  body gave, or "Advisory" when none did), why it matters, the evidence
  ("22 ports: Fa1/0/3, Fa1/0/4, Fa1/0/5 and 19 more."), the fix, and its
  references as links ("DISA STIG V-220630, CAT II", "Related: ..." when the
  rule is related rather than exact);
- the checks that could not be decided (unknown, not checked), one quiet line
  each with the reason.

A device without checks says why: it was never polled, the graph predates the
checks, or the graph's checks came from captures that did not include it.
Configuration findings do not change the risk colour or score. The overview's
"Device configuration" panel counts the failed checks of every checked device
by severity.

A telnet or HTTP finding from the connection test says "TCP port 23 accepted
a connection from the scanner." A spare-port finding names each port with its
VLAN ("Fa1/0/5 (VLAN 40)") and says how many of them are enabled and how many
shut down, and how many ports lost their link after boot and are not counted.

## Unmanaged hosts

A host without a Wazuh agent (see "Unmanaged hosts" in
`../backend/README.md`) carries an **Unmanaged** label in the top left corner
of its node on the map. The label does not change the risk border. Its detail
flyout shows an "Unmanaged" badge and one sentence: "No Wazuh agent reports
from this machine, so its software and vulnerabilities are not known." The
Identity section adds:

- **Manufacturer**: the maker from the MAC address, "Randomised or virtual
  address (names no manufacturer)" for a locally administered one, or "Not in
  the IEEE registry". Managed hosts show this line too.
- **Name from**: "Reverse DNS" or "Its own SNMP system name", when the name
  did not come from Wazuh.
- **SNMP reports**: the system description, when the host answered the SNMP
  question. Such a host's software is then looked up like a device's, and its
  Vulnerabilities section reads like a device's ("Potential: matched by
  software version ...").

The overview's **Agent coverage** panel says, for example, "7 of 10 hosts
have a Wazuh agent", how many are unmanaged, and why it matters (CIS Controls
v8.1 Control 1 and NIST SP 800-53 CM-8 ask for an inventory of every asset).
It is information, not a finding: the other totals do not change.

## Active checks

Scan settings groups three switches under "Active checks: optional, off by
default". Each sends something the scan otherwise would not, and each says
what in one sentence:

- "Also test factory-default SNMP names (public, private)": each device gets
  two extra read-only SNMP requests with those names, which the network may
  log as failed logins (`--check-default-communities`).
- "Test whether telnet and web management answer on devices that do not
  report it": one TCP connection to port 23 and one to port 80 of each such
  device, closed at once; nothing is sent and no login is tried
  (`--check-management-ports`).
- "Ask unmanaged hosts for their identity over SNMP": the scan's SNMP
  credential goes to every host without an agent (at most 256), and those
  machines are not verified; a hostile one receives the credential
  (`--probe-unmanaged-snmp`).
- "Service-scan unmanaged hosts with nmap": `nmap -sV` actively connects to
  and probes the discovered unmanaged hosts for open ports and service
  versions, then looks those up in NVD for potential CVEs; never managed hosts
  or network devices, and nmap must be installed on the dashboard server
  (`--nmap-unmanaged`).

The config keys above set where each switch starts. The scan request carries
the switches' positions; an automatic rescan keeps the choices of the last
scan.

## Vulnerability report

The **Vulnerability report** page turns the three files a scan produces
(`graph.json`, `vulnerabilities.json`, `attack_paths.json`) into one report —
on screen and as an A4 PDF. It only displays data the scan produced; it changes
no scanner or engine.

Two modes, chosen by a switch at the top:

- **Most vulnerable assets**: assets ranked worst-first (by displayed risk
  level, then confirmed-critical count, then total CVEs), each a compact block
  with its counts by severity split into confirmed and potential, its worst
  CVEs and its configuration findings. A configurable top N (default 10) shows;
  the rest are collapsed.
- **Single asset**: one asset's full detail — identity, open ports and detected
  services, every CVE, every configuration finding with its remediation, and
  whether it lies on an attack path.

A finding is **confirmed** when a Wazuh agent reports from the host, and
**potential** when it is matched against the NVD by software version (network
devices, hosts without an agent, and services detected by nmap). Three filters
apply on screen and carry into the PDF: severity (critical/high/medium/low/
unknown), confidence (all / confirmed only / potential only) and on-path (only
assets a route passes through). Because a host can carry thousands of CVEs, each
asset shows its worst 10 with "show all N" on demand, and the PDF caps each
asset's CVE table at a configurable number (default 200) with a "showing the
200 worst of N" line.

**Export PDF** calls the browser's print; its "Save as PDF" writes a multi-page
A4 file with a cover, executive summary, methodology and sources, findings and
remediation. A print stylesheet hides the dashboard and plugin chrome, forces a
light document, and starts each section on its own page. Keep the print
dialog's "Headers and footers" on for page numbers. The organisation name on
the cover comes from `vulnmapper.reportOrg`.

## Recommendations

The **Recommendations** page aggregates every asset's honest recommended action
(the same logic as the vulnerability report's remediation) into one
network-wide, prioritised plan. Instead of reading fixes asset by asset, each
distinct action appears once, listing the assets it affects, ranked worst-first
(severity, then how many assets, then how many lie on an attack path). It
invents nothing: configuration fixes use the checklist's stored remediation text
verbatim, and CVE guidance stays generic and never names an invented fixed
version. There is no PDF export; it is on screen only.

A header shows progress ("5 of 14 addressed") and filters by status and
severity. Each item carries a status — Open, In progress, Done or Accepted risk
— set from the page. Statuses are a **shared tracker** kept in
`recommendations.json` beside the graph (the same place as `targets.json`),
written through a server route, so every viewer sees the same statuses and they
survive rescans. `open` is the default and is not stored, so the file holds only
items moved off Open; a finding that a rescan clears silently drops off the plan.

## Development setup

1. Check out OpenSearch Dashboards 2.19.3 and use Node 18.19.0 (`nvm use 18.19.0`).
2. Make this folder appear as `plugins/vulnmapper` inside the dashboard
   checkout, for example with a bind mount:

   ```
   sudo mount --bind ~/dev/Wazuh-Network-Mapper/plugin ~/dev/OpenSearch-Dashboards/plugins/vulnmapper
   mountpoint ~/dev/OpenSearch-Dashboards/plugins/vulnmapper
   ```

3. From the dashboard folder run `yarn osd bootstrap`, then
   `yarn start --no-base-path`. The plugin is at
   http://localhost:5601/app/vulnmapper.

`yarn start` runs in `--dev` mode, which also loads
`config/opensearch_dashboards.dev.yml` from the dashboard checkout. That file
lives outside this repository; its full contents here are:

```yaml
# Development-only settings, loaded automatically by `yarn start` (--dev mode).
vulnmapper.backendDir: /home/ans/dev/Wazuh-Network-Mapper/backend
vulnmapper.graphPath: /home/ans/dev/Wazuh-Network-Mapper/data/graph.json
vulnmapper.pythonBin: /home/ans/dev/venv/bin/python
```

Type-check from the dashboard folder with
`node_modules/.bin/tsc -p plugins/vulnmapper/tsconfig.json --noEmit`.

Unit tests for the plugin's pure helpers (`*.test.ts`) run with the
dashboard's own jest, from the dashboard folder:
`node_modules/.bin/jest --config plugins/vulnmapper/test/jest.config.js`.

## API

| Route | Purpose |
|---|---|
| `GET /api/vulnmapper/graph` | the current graph; file time in the `x-vulnmapper-graph-mtime` header |
| `POST /api/vulnmapper/scan` | start a scan; body `{ "community"?: string, "checkDefaultCommunities"?: boolean, "checkManagementPorts"?: boolean, "probeUnmanagedSnmp"?: boolean }` (each switch defaults to its `vulnmapper.*` key); 409 if one is running |
| `GET /api/vulnmapper/scan/status` | `idle`, `running` or `failed`, with a message, `stage` (the stage the scanner last announced, while running), `nmapAvailable` (nmap is on the server's PATH) and `defaults: { checkDefaultCommunities, checkManagementPorts, probeUnmanagedSnmp, nmapUnmanaged }` for the scan form |
| `GET /api/vulnmapper/liveness` | `{ enabled, intervalSeconds, checkedAt, nodes, graphMtime }`; `checkedAt` null and `nodes` empty when disabled or before the first pass; `graphMtime` is the graph file's modified time (null if there is none) |
| `GET /api/vulnmapper/attack-paths` | the computed `attack_paths.json` read from beside the graph; a missing file is returned as `{ metadata: { state: "absent" }, ... }` rather than an error |
| `GET /api/vulnmapper/vulnerabilities` | the full per-asset CVE list (`vulnerabilities.json`) read from beside the graph, plus `org` (from `vulnmapper.reportOrg`); a missing file is returned as `{ metadata: { state: "absent" }, cves: {}, hosts: {}, org }` rather than an error |
| `POST /api/vulnmapper/targets` | mark, re-rate or unmark one protected asset; body `{ "id": string, "importance": "high" \| "moderate" \| "low" \| null }` (null unmarks); updates `targets.json` beside the graph and runs `<pythonBin> -m vulnmapper.attackpaths --graph <graphPath>` to recompute (with `--liveness <liveness.json>` when liveness is on) |
| `GET /api/vulnmapper/schedule` | the scan schedule: `{ frequency, dailyHour, lastRun, nextRun, timeZone }` (`frequency` is `off`, `1h`, `3h`, `6h`, `12h` or `daily`; times are ISO, shown in the server's `timeZone`) |
| `POST /api/vulnmapper/schedule` | set the schedule; body `{ "frequency": ..., "dailyHour": 0-23 }`; saved atomically to `schedule.json` beside the graph and the timer re-armed. Scheduled scans run with every active check off and the SNMP credential from the server environment |
| `GET /api/vulnmapper/history` | the scan history index (`history/index.json` beside the graph), newest first, at most 10: `{ id, time, trigger, files, counts, stages }` per scan; `[]` before the first |
| `GET /api/vulnmapper/history/{id}/changes` | `{ current, previous }`: that archived scan's `graph`, `vulns` and `attackPaths` and the previous scan's (`previous` null for the oldest); 404 for an id not in the index, 400 for one not in the id format |
| `GET /api/vulnmapper/recommendations` | the shared recommendations tracker (`recommendations.json`) read from beside the graph; a missing file is returned as `{ "statuses": {} }` rather than an error |
| `POST /api/vulnmapper/recommendations/status` | set one item's status; body `{ "key": string, "status": "open" \| "in_progress" \| "done" \| "accepted_risk" }`; updates `recommendations.json` beside the graph (`open` deletes the entry) and returns the updated file. Writes a local file only — it runs no scanner or process |

A scan runs `<pythonBin> -m vulnmapper` in `backendDir`, one at a time. The
graph file is replaced only when the scanner exits cleanly with valid JSON, so
a failed scan keeps the previous graph. `vulnerabilities.json` and
`attack_paths.json` (from `targets.json`) are written beside the graph and moved
into place only with it.

## Liveness (optional)

A background check of whether the nodes already on the map still answer. Off
by default; turn it on in `opensearch_dashboards.yml` (or the dev config):

```yaml
vulnmapper.liveness.enabled: true                  # default false
vulnmapper.liveness.intervalSeconds: 10            # default 10, at least 10
vulnmapper.liveness.missThreshold: 2               # default 2, at least 1
vulnmapper.liveness.agentMaxAgeSeconds: 30         # default 30, at least 10
vulnmapper.liveness.autoRescan: true               # default true
vulnmapper.liveness.minRescanIntervalSeconds: 120  # default 120, at least 60
# vulnmapper.liveness.path: /path/to/liveness.json # default: beside graphPath
```

Every interval the server runs `<pythonBin> -m vulnmapper.liveness` (skipped
while a scan runs) and saves the result to `liveness.json`; it never writes the
graph. The SNMP community of the last scan is passed through the environment
only. Endpoints with a Wazuh agent are checked by agent check-in when
`WAZUH_PASS` is in the dashboard server's environment (the same variable a
scan uses): a check-in older than `agentMaxAgeSeconds` is a miss, and a
disconnected agent is inactive at once. When the host's switch port goes down,
it is inactive at once: a check-in counts again only if it is later than the
moment the port was first seen down. Without `WAZUH_PASS` they are pinged.

When a pass sees something new (a switch port came up with nothing on the map
linked to it, or an active Wazuh agent that is not on the map) and
`autoRescan` is on, the server starts a scan the way the Scan settings page
does: never while one is running, and never sooner than
`minRescanIntervalSeconds` after the last scan started. The map reloads the
graph by itself when the graph file changes.

Wi-Fi clients of an access point are checked against the AP's client list
(a client that leaves it is inactive at once), and a wired host that ignores
ping is confirmed from its switch's MAC table.

An access point found by the scan (over CDP, for a Cisco AP) shows a Wi-Fi
icon; its clients hang off it on short teal dotted links, and the flyout
shows its client count, or for a client its SSID, access point and radio.

On the map, inactive devices stay on the canvas, dimmed. An offline host (its
Wazuh agent disconnected or never connected, or liveness reports it inactive)
leaves the topology: with "Hide inactive hosts" on it is not shown at all (an
open detail flyout on it closes); with it off it is listed greyed in an
"Inactive (n)" column on the right with its name or IP, MAC, last seen time
and how it was checked. The detail flyout shows a Liveness row, for example
"via Wazuh agent check-in, 8 s ago". The same offline rule leaves those hosts
out of the vulnerability report and the recommendations.

## Building the zip

Stop the development server first, then from this folder (inside the dashboard
checkout):

```
yarn build --opensearch-dashboards-version 2.19.3
```

The result is `build/vulnmapper-2.19.3.zip`. `scripts/send-plugin.sh` runs the
same build and copies the zip to the server; the version it builds for, and
the one `scripts/run.sh` runs, is set once in `scripts/osd-version.sh`.
Installing it into a Wazuh dashboard has not been tested yet.

## Known limitations

- **Community strings with commas, spaces or quotes.** The community is passed
  to the scanner in the `SNMP_COMMUNITIES` environment variable, never on the
  command line. The scanner splits that variable (and `SNMP_COMMUNITY`) on
  commas and whitespace and parses it with `shlex`. So a community containing
  a comma or space is treated as several communities, quotes and backslashes
  are interpreted, and an unbalanced quote makes the scan fail.
- **Device findings are potential.** They match the device's software
  version; whether the affected feature is in use on that device is not
  checked.
- **Scan state lives in server memory.** It resets when the dashboard server
  restarts.
