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
- `--help`: list every option.

## Output

The graph is written to stdout, or to the file given with `-o`. The web app
reads `data/graph.json` at the repository root, and scans started from the web
app write to that file.

## Tests

From `backend/`:

```
python -m unittest discover -s tests
```

The tests use fixtures only and need no network access or credentials.
