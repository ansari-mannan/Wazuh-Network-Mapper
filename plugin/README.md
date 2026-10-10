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
- Vulnerabilities, Attack paths and Recommendations: shown as "Coming soon".

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

The config keys above set where each switch starts. The scan request carries
the switches' positions; an automatic rescan keeps the choices of the last
scan.

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
| `GET /api/vulnmapper/scan/status` | `idle`, `running` or `failed`, with a message, and `defaults: { checkDefaultCommunities, checkManagementPorts, probeUnmanagedSnmp }` for the scan form |
| `GET /api/vulnmapper/liveness` | `{ enabled, intervalSeconds, checkedAt, nodes, graphMtime }`; `checkedAt` null and `nodes` empty when disabled or before the first pass; `graphMtime` is the graph file's modified time (null if there is none) |
| `GET /api/vulnmapper/attack-paths` | the computed `attack_paths.json` read from beside the graph; a missing file is returned as `{ metadata: { state: "absent" }, ... }` rather than an error |
| `POST /api/vulnmapper/targets` | mark, re-rate or unmark one protected asset; body `{ "id": string, "importance": "high" \| "moderate" \| "low" \| null }` (null unmarks); updates `targets.json` beside the graph and runs `<pythonBin> -m vulnmapper.attackpaths --graph <graphPath>` to recompute |

A scan runs `<pythonBin> -m vulnmapper` in `backendDir`, one at a time. The
graph file is replaced only when the scanner exits cleanly with valid JSON, so
a failed scan keeps the previous graph.

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

On the map, inactive devices stay on the canvas, dimmed; every inactive host
leaves it for an "Inactive (n)" panel (switch "Hide inactive hosts") showing
its name or IP, MAC, last seen time and how it was checked. The detail flyout
shows a Liveness row, for example "via Wazuh agent check-in, 8 s ago". With
liveness disabled the UI is unchanged.

## Building the zip

Stop the development server first, then from this folder (inside the dashboard
checkout):

```
yarn build --opensearch-dashboards-version 2.19.3
```

The result is `build/vulnmapper-2.19.3.zip`. Installing it into a Wazuh
dashboard has not been tested yet.

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
