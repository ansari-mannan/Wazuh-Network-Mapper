# vulnmapper GUI (POC dev tool)

A standalone web app that visualizes the `vulnmapper` scanner's `graph.json` as a
laid-out network topology with per-device / per-endpoint detail. This is a
**developer tool**, not the OpenSearch Dashboards plugin — see the note at the
bottom on how it folds into the real plugin later.

It does **not** modify the Python scanner or the format of `graph.json`.

```
gui/
  backend/    Express API: serves graph.json, spawns the scanner
  frontend/   Vite + React app: React Flow topology + detail screens
```

## Stack note

The task brief said "react (next.js) + Vite". Next.js and Vite are alternative
React toolchains — you don't use both. Since the backend is a separate Express
service, this POC is a **Vite + React SPA** talking to Express over `/api/*`
(the natural pairing). The React components carry over unchanged when this later
becomes the Dashboards plugin; only the Express layer is replaced.

## Prerequisites

- Node 18+ (developed on Node 24)
- For live scans only: Python 3 with the `vulnmapper` package importable from the
  repo root (`python -m vulnmapper ...`). Not needed just to view a graph.

## Install

From this `gui/` directory:

```bash
npm run install:all      # installs root + backend + frontend deps
```

(or install each of `.`, `backend/`, `frontend/` individually.)

## Run

```bash
npm run dev              # starts BOTH backend (:3001) and frontend (:5173)
```

Then open **http://localhost:5173**. Vite proxies `/api/*` to the backend, so the
browser only ever talks to `/api` — the graph is never bundled into the frontend.

Run them separately if you prefer:

```bash
npm --prefix backend run dev      # http://localhost:3001
npm --prefix frontend run dev     # http://localhost:5173
```

## Where graph.json lives

By default the backend reads/writes the repo's `graph.json` (one level above
`gui/`, i.e. `../graph.json` from the backend). Override with an env var:

```bash
GRAPH_PATH=/abs/path/to/graph.json npm --prefix backend run dev
```

The scanner writes its graph there with:

```bash
python -m vulnmapper --community cyfor123 > graph.json
```

## Backend API

| Method | Route               | Purpose                                                       |
|--------|---------------------|---------------------------------------------------------------|
| GET    | `/api/config`       | default community string (pre-fills the input; def. `cyfor123`)|
| GET    | `/api/graph`        | read `graph.json` fresh from disk and return it               |
| POST   | `/api/scan`         | spawn `python -m vulnmapper --community <c>`, async; 202 + `running` |
| GET    | `/api/scan/status`  | `idle` \| `running` \| `done` \| `error` (+ `error` message)  |

`POST /api/scan` only succeeds on a host with lab access. **At home it will fail**
(no SNMP targets / no Wazuh) — that's expected: the scan returns an `error`
status, the UI shows the message, and the currently displayed graph is left
untouched. On success the scanner's stdout is validated as JSON and written to
`GRAPH_PATH`, then the UI refetches it.

### Env vars (backend)

| Var                | Default                              | Meaning                          |
|--------------------|--------------------------------------|----------------------------------|
| `PORT`             | `3001`                               | backend port                     |
| `GRAPH_PATH`       | `<repo>/graph.json`                  | graph file to read/write         |
| `DEFAULT_COMMUNITY`| `cyfor123`                           | pre-filled community string      |
| `PYTHON_BIN`       | `python` (Windows) / `python3` (*nix)| interpreter used for live scans  |

## Two screens

**Topology** (landing) — React Flow + dagre hierarchical layout. Root is the node
with `parent_id == null` (e.g. the L3-Switch) at the top, devices/hosts below.
Custom node icons by role (switch / router / firewall / host / server / unknown),
a subtle risk dot, and dimmed-dashed offline nodes. Click a node for detail.

**Device detail** — full identity block; for endpoints, the `top_cves` list is the
centerpiece; for devices, `port_status` rendered as a grid of green (up) / red
(down) presence dots, plus neighbor/uplink ports. Back returns to the topology.

### Risk dot colors

| `risk_score` | color  | meaning                         |
|--------------|--------|---------------------------------|
| `>= 9`       | red    | critical                        |
| `7 – 9`      | orange | high                            |
| `> 0 & < 7`  | yellow | low / medium                    |
| `== 0`       | green  | scored, clean                   |
| `null`       | grey   | unknown / unscored (never green)|

## How this folds into the OpenSearch Dashboards plugin later

The React layer (`frontend/src` — `layout.js`, `icons.jsx`, `nodeStyle.js`, the
components) is the durable part and moves into the plugin's React app essentially
as-is. The **Express logic in `backend/server.js` becomes a Dashboards server
extension** (route handlers registered on the plugin's `router`): `/api/graph`
reads the same artifact, `/api/scan` shells out to the pipeline. The `/api/*`
contract the frontend depends on stays identical, so the UI doesn't change.
