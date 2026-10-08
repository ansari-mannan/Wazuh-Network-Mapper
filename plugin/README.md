# vulnmapper: Network Topology Mapper plugin

An OpenSearch Dashboards plugin that shows the network topology graph produced
by the Python scanner in `../backend`. It appears in the dashboard's left menu
as **Network Topology Mapper** and has:

- **Overview**: network devices by type, endpoints by status, hosts by risk
  level, and cards for every page.
- **Topology map**: the graph, with draggable nodes, reload and reset, and a
  detail flyout for each device or endpoint. A link between two devices shows
  each device's port next to that device; a host link shows the switch port.
- **Scan settings**: run a scan with an SNMP community string, follow its
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

`backendDir` and `graphPath` have no default; until they are set, the API
returns an error saying which key is missing.

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
| `POST /api/vulnmapper/scan` | start a scan; body `{ "community"?: string }`; 409 if one is running |
| `GET /api/vulnmapper/scan/status` | `idle`, `running` or `failed`, with a message |
| `GET /api/vulnmapper/liveness` | `{ enabled, intervalSeconds, checkedAt, nodes, graphMtime }`; `checkedAt` null and `nodes` empty when disabled or before the first pass; `graphMtime` is the graph file's modified time (null if there is none) |

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
- **Device risk.** Network devices have no CVE data yet, so the plugin shows a
  device as Unscored unless it carries CVE data (`max_cvss` or a CVE list),
  even though the scanner writes `risk_score: 0` for it.
- **Scan state lives in server memory.** It resets when the dashboard server
  restarts.
