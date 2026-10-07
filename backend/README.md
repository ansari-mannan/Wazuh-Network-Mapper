# vulnmapper (backend)

`vulnmapper` is the Python scanner. It collects endpoints and their CVEs from
Wazuh (Manager API and Indexer), crawls the network over SNMP/LLDP from a seed
device, and merges both into one graph document with `nodes`, `edges` and
`metadata`.

## Layout

- `vulnmapper/`: the scanner package (`python -m vulnmapper`).
- `tests/`: unit tests, golden files and fixtures.
- `scripts/`: maintenance scripts (`_freeze_golden.py` refreshes the golden
  files; `verify_comware.py` checks an HP Comware switch over SNMP).
- `requirements.txt`: third-party packages.

## Install

Python 3.10 or later. From `backend/`:

```
python -m pip install -r requirements.txt
```

## Run

Run from `backend/`. Credentials come from environment variables only; see
`../frontend/.env.example` for the full list. A stage that needs a credential
exits with a one-line message if it is not set.

```
python -m vulnmapper --community <community> -o ../data/graph.json
```

Useful options:

- `--no-endpoints` / `--no-network`: build a graph from one side only.
- `--scored PATH` / `--network PATH`: use saved stage output instead of a live run.
- `--seed IP`: start the crawl from a specific device.
- `--vulns-out PATH`: where to write `vulnerabilities.json` (see below).
- `--help`: list every option.

## Output

The graph is written to stdout, or to the file given with `-o`. The web app
reads `data/graph.json` at the repository root, and scans started from the web
app write to that file.

An endpoint is attached to a switch port from LLDP or the forwarding tables.
Only an endpoint whose Wazuh status is `active` and has no such evidence is
attached by subnet instead (to a device sharing its /24, confidence
`subnet_fallback`); any other endpoint without evidence stays unparented and
is listed in `metadata.unparented_endpoints` with its reason.

### CVEs and the base score

The score stage reads every vulnerability document for each agent (paged, at
most 20000 per agent). Problems are reported in `metadata.warnings` rather than
failing the scan:

- `cve_cap_reached`: an agent had more than 20000 documents; the rest were not read.
- `indexer_unreachable`: the indexer failed; the listed endpoints are unscored.
- `not_yet_inventoried`: no vulnerability documents and no package inventory
  either, so Wazuh has not examined the agent yet; it is unscored, not 0.0.
- `inventory_unavailable`: syscollector data could not be read (after one retry
  3 seconds later for a 5xx or a timeout); the agent's place on the map may be
  incomplete.
- `wazuh_server_skipped`: see below.

The score stage needs `WAZUH_PASS` as well as `INDEXER_PASS`, for the package
check.

The Wazuh server itself (agent 000) is included, marked `is_wazuh_server: true`.
The Manager API reports it as 127.0.0.1, so its real IPv4 is taken from its
inventory (the interface with the default gateway, else the first address that
is not loopback, link-local or a container bridge); that address lets it merge
with the host found in the switch tables. If no such address exists, it is left
out of that scan with a `wazuh_server_skipped` note.

Each endpoint node in the graph carries:

- `risk_score`: the base score, 0.0 to 10.0. `null` means the endpoint could
  not be scored; `0.0` means it was scanned and nothing was found.
- `max_cvss`: the highest CVSS among its CVEs.
- `cve_summary`: `{total, critical, high, medium, low, unknown, max_cvss}`,
  counting distinct CVEs by CVSS v3 band (critical 9.0+, high 7.0-8.9,
  medium 4.0-6.9, low below 4.0, unknown = no score). `null` when not scored.
- `top_cves`: the 10 worst distinct CVEs, each with `cve`, `cvss`,
  `cvss_version`, `severity`, `package`, `version`, `description` and, when the
  indexer has them, `reference`, `published_at`, `detected_at`.

The base score (`vulnmapper/scoring.py`, a placeholder to be replaced) is:

```
weighted = 10*critical + 5*high + 2*medium + 1*low      (distinct CVEs)
volume   = min(1, log10(1 + weighted) / log10(1 + 10000))
score    = 0.7 * max_cvss + 0.3 * 10 * volume
```

A single 9.8 scores 7.6; a hundred criticals with a 9.8 worst score 9.1; the
volume term saturates at a thousand criticals (9.9).

The complete list goes to a second file, `vulnerabilities.json`. It is written
to `--vulns-out PATH`, else next to the `-o` file; when the graph goes to stdout
and `--vulns-out` is not given, it is skipped. It is written only when the scan
succeeds (via a temp file and rename), as compact JSON:

```
{
  "metadata": {"scan_time": "...", "counts": {"hosts": 0, "cves": 0, "findings": 0}},
  "cves":  {"<CVE id>": {"cvss", "cvss_version", "severity", "description",
                         "reference", "published_at"}},
  "hosts": {"<node_id>": {"hostname", "agent_id",
                          "findings": [{"cve", "package", "version", "detected_at"}]}}
}
```

Each CVE's text is stored once in `cves`; hosts list one finding per CVE and
package. Host keys are the graph's `node_id` values. `findings` is `null` when
the host was not scored or came from an old `--scored` file.

`--scored PATH` reads `{"endpoints": [...], "cves": {...}, "warnings": [...]}`
(what `python -m vulnmapper.endpoints.score` writes) or the older plain list of
endpoints, which keeps its stored `risk_score` and has no full findings.

## Liveness

```
python -m vulnmapper.liveness --graph ../data/graph.json [--state liveness.json]
                              [--threshold 2] [--agent-max-age 60]
```

Re-checks the nodes already in the graph (never writes it) and prints a state
document on stdout: per node `state` (`active` / `inactive` / `unknown`),
`method`, `misses`, `last_seen`, `last_checked`, `proven_methods`.

- Endpoints with an `agent_id` are checked by Wazuh agent check-in
  (`method: "agent"`) when `WAZUH_PASS` is set: one Manager API request per
  pass lists every agent's status and `lastKeepAlive`. Active with a check-in
  no older than `--agent-max-age` seconds is a reply (agent 000, the manager,
  always is); an older check-in is a miss; `disconnected`, `pending` or
  `never_connected` makes the node inactive at once. If the login or request
  fails or takes over 5 seconds, those nodes keep their state for the pass
  (`reason: "agent_unavailable"`, and `agent_error` in the document). Without
  `WAZUH_PASS` they are pinged like any other endpoint.
- Pollable devices are probed by SNMP when `SNMP_COMMUNITIES` (or the other
  `SNMP_*` variables) is set, everything else by `ping -c 1 -W 1`.
- A node goes inactive after `--threshold` misses on a method it has answered
  before (`agent` counts as answered from the start), or at once when its
  switch port is reported down (`method: "port"`). Such a node gets its
  earlier state back, with misses reset, once that port is up again or a new
  scan places it on another port; an up port never makes a node active by
  itself.
- Port states of every polled device are remembered between passes (`ports`).
  The document sets `rescan_suggested` with short `rescan_reasons` when a port
  goes from down to up with nothing in the graph linked to it, or when the
  Manager API lists an active agent that is not in the graph. The suggestion
  stands until a new scan replaces the graph (`graph_scan_time`).

Credentials come from the environment only and are never logged, written or
placed in argv. The plugin runs it on a timer and starts the suggested scans.

## Tests

From `backend/`:

```
python -m unittest discover -s tests
```

The tests use fixtures only and need no network access or credentials.
