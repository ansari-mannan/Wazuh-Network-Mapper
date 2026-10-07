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

### CVEs and the base score

The score stage reads every vulnerability document for each agent (paged, at
most 20000 per agent; an agent over the cap gets a `cve_cap_reached` warning in
`metadata.warnings`). If the indexer cannot be reached, the scan still finishes:
the affected endpoints are left unscored and an `indexer_unreachable` warning
lists them.

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
volume   = min(1, log10(1 + weighted) / log10(1 + 1000))
score    = 0.7 * max_cvss + 0.3 * 10 * volume
```

A single 9.8 scores 7.9; a hundred criticals with a 9.8 worst score 9.9.

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

## Tests

From `backend/`:

```
python -m unittest discover -s tests
```

The tests use fixtures only and need no network access or credentials.
