# Merge Verification Report — VulnMapper UI + POC

Merged the POC (`Wazuh-Network-Mapper`, Express + Vite/React) and the final Next.js UI
(`Wazuh Vulnerability Mapper(UI)`) into a single Next.js app at the repo root. This report
records what was ported verbatim vs. adapted vs. newly written, the hardcoded values chosen
for each de-functionalized page, environment limitations, and build status.

## Baseline (Phase 0)

- Copied the Next.js UI into the repo root (preserved the POC's `.git`, `graph.json`,
  `vulnmapper/`, `tests/`). `node_modules` copied and reconciled with `npm install` (387 pkgs,
  up to date).
- Baseline `npm run build` **passed** before any edits.
- `graph.json` (real CYFOR lab, 10 nodes), `vulnmapper/` (Python pipeline), and `tests/` were
  already at the repo root and left untouched.

## Phase 1 — Backend API routes (NEW, behavior ported from `gui/backend/server.js`)

| File | Notes |
|---|---|
| `app/api/config/route.ts` | `GET → { community }` from `DEFAULT_COMMUNITY` env, fallback `"cyfor123"`. |
| `app/api/graph/route.ts` | `GET` reads `graph.json` fresh from disk every request (`force-dynamic`). 404 on read error, 500 on parse error — exact POC messages. |
| `app/api/scan/route.ts` | `POST` spawns `python -m vulnmapper --community <c>` (no shell, args array), writes validated stdout to `graph.json`, responds `202 {status:"running"}`. 409 if already running. |
| `app/api/scan/status/route.ts` | `GET` returns shared scan state. |
| `lib/scanState.ts` | Module-level shared `let` state, imported by both scan routes so status persists across requests in one server process. |

**Verified (Phase 1 gate):**
- `GET /api/config` → `{"community":"cyfor123"}` ✅
- `GET /api/graph` → `metadata.counts.nodes === 10` ✅
- `POST /api/scan {"community":"test"}` → `202 {"status":"running"}`, then `/api/scan/status`
  transitions to `error` with the Python stderr (does **not** hang, does **not** crash, does
  **not** overwrite the good `graph.json`) ✅

## Phase 2 — Shared API client (NEW, ported from `gui/frontend/src/api.js`)

`lib/vulnmapperApi.ts`: `getConfig`, `getGraph`, `startScan`, `getScanStatus` (same-origin,
throws on non-2xx except 202 via an `asJson` helper). Also defines the graph TypeScript types
(`GraphNode` as a `DeviceNode | EndpointNode` union, `CVE`, `GraphEdge`, `Metadata`,
`GraphResponse`) modelled on the real `graph.json` shape.

## Phase 3 — Topology Map (POC-faithful, real data)

Ported into `risk-module/ui/poc/` (JSX→TSX, `reactflow`→`@xyflow/react`):

| New file | Source | Port type |
|---|---|---|
| `poc/icons.ts` | `icons.jsx` | verbatim (typed) |
| `poc/nodeStyle.ts` | `nodeStyle.js` | verbatim (typed) — same thresholds, null=grey semantics |
| `poc/layout.ts` | `layout.js` | verbatim (typed) — dagre TB, `parent_id`-driven, NODE_W/H 184/84 |
| `poc/CustomNode.tsx` | `components/CustomNode.jsx` | adapted — `@xyflow/react` `Handle`/`Position`, `NodeProps` typing |
| `poc/PocTopologyView.tsx` | `components/TopologyView.jsx` | adapted — `@xyflow/react` `ReactFlow`/`Background`/`Controls`/`MarkerType`; imports `@xyflow/react/dist/style.css` |
| `poc/poc-theme.css` | `styles.css` | adapted — all node/detail rules scoped under `.poc-scope` so they don't bleed into the Tailwind dashboard |

`risk-module/ui/screens/TopologyMap.tsx` rewritten: client `getGraph()` on mount + "Load
Graph" refresh button, counts strip, error state, canvas inside dashboard chrome. Node click →
`router.push("/dashboard/asset/" + encodeURIComponent(nodeId))` (node ids contain colons, so
encode/decode is required on both ends).

## Phase 4 — Asset / Device Detail (POC-faithful, real data)

- `risk-module/ui/poc/PocDeviceDetail.tsx` — adapted from `components/DeviceDetail.jsx` (same
  `Field` helper, Identity card, endpoint Vulnerabilities card with the "unscored" empty state,
  device Ports + Topology ports cards).
- `risk-module/ui/screens/AssetDetail.tsx` rewritten: client `getGraph()`, `decodeURIComponent`
  of the route param, `find(n => n.node_id === id)`. Found → `PocDeviceDetail`; not found →
  calm "Asset not found." (the expected path for mock ids like `web-srv-01`).

**Verified (Phase 3/4 gate):** topology page and asset pages for real node ids
(`device:00:23:ac:e5:74:00`, `endpoint:001`) return 200 against the live `/api/graph` (10
nodes); a mock id (`web-srv-01`) returns 200 in the calm not-found state.

## Phase 5 — Scan Configuration (must work)

`risk-module/ui/screens/ScanConfiguration.tsx`: added an **SNMP Community String** input,
prefilled from `getConfig()` on mount. "Start Scan" now calls `startScan(community)` and polls
`getScanStatus()` every 1s (timers cleared on unmount). Running shows an indeterminate progress
bar with a generic "Scan in progress…" label (no false stage claims). `done` → success card +
link to `/dashboard/topology`; `error` → surfaces `scan.error` without throwing. Schedule /
Scan Type remain decorative local state; the Previous Scans table is left as hardcoded mock
rows.

## Phase 6 — De-functionalized pages (inert, hardcoded; layout unchanged)

All replaced the `risk-module` "risk engine" calls with static literals. None introduce
loading/error states or console errors.

- **`RiskDashboard.tsx`** — tiles: Total Hosts **32**, Vulnerabilities Found **89**, Critical
  Hosts **4**, Attack Paths **3**. Risk Overview has 8 bars, exactly **4 red** (>7:
  web-srv-01 9.4, db-srv-01 8.9, dc-01 8.1, app-srv-02 7.6) matching Critical Hosts = 4.
  6 static Recent Alerts. "Run New Scan" is a plain no-op button. Last scan timestamp static.
- **`VulnerabilityReport.tsx`** — severity pills render ("ALL" active) but inert; table shows
  12 hardcoded rows always. 6 hardcoded per-device cards; the `<Link>` was removed (now plain
  `<div>`) so cards don't navigate to a dead mock asset id.
- **`AttackPathAnalysis.tsx`** — 3 hardcoded path objects (scores 27.4 / 22.7 / 16.7); click-to-
  select retained; added an "Implementation Note" card stating the Dijkstra/A* engine is not yet
  implemented. Path Topology graph + Timeline + Risk Narrative still render off the selected
  hardcoded path (Path Topology still uses the mock topology graph, unchanged).
- **`Recommendations.tsx`** — filter pills and Mark Resolved/Reopen buttons render but inert.
  9 hardcoded recommendations with baked `status`: **6 open · 3 resolved** (header counts match).
- **`ExecutiveReport.tsx`** — `Total Environment Risk: 7.4`, 5 hardcoded top high-risk assets.
  Disabled JSON/PDF buttons + "(Placeholder — not functional in MVP)" caption left as-is.
- **`RiskModelExplanation.tsx`** — unchanged (already static prose).
- **`TopologyLegend.tsx`** — unchanged (already carries its own "should be driven from live
  topology metadata" note; still renders off mock data without errors — left per the
  low-priority guidance).

> Note: the mock data on these pages (`web-srv-01`, `db-srv-01`, …) intentionally does **not**
> match the real CYFOR topology (`L3-Switch`, `CYFOR-1/2/3`, …). That mismatch is part of the
> "unfinished project" texture and is deliberately not unified.

## Phase 7 — Cleanup & final verification

- Deleted `src/` (legacy Vite app, unused — confirmed not referenced by the Next build).
- Deleted `gui/` (POC Express backend + Vite frontend) after Phases 1–4 were verified against it.
- Kept `vulnmapper/`, `graph.json`, `tests/` at the repo root.
- **`npm run build` passes** with no TypeScript errors (17 routes generated; 4 API routes are
  dynamic, the rest static/SSR).

### Runtime smoke test (production `npm start`)

All sidebar/dashboard routes returned **200**: `/dashboard`, `/dashboard/topology`,
`/dashboard/asset/<encoded real id>` (device + endpoint), `/dashboard/vulnerability-report`,
`/dashboard/attack-path`, `/dashboard/recommendations`, `/dashboard/scan-configuration`,
`/dashboard/report`, `/dashboard/risk-model`, `/dashboard/topology-legend`. The live
`/api/graph` served the real 10-node graph throughout.

## Environment limitations

- The real scan (`POST /api/scan`) **wiring is correct** but the Python pipeline could not
  complete in this sandbox: `ModuleNotFoundError: No module named 'urllib3'` (Python deps for
  `vulnmapper` are not installed, and the CYFOR lab network is unreachable here). The route
  correctly captured the stderr, set `status:"error"`, and left the existing `graph.json`
  intact — exactly the intended failure path. Installing the `vulnmapper` Python requirements
  and running on the lab network would let a scan complete and overwrite `graph.json`.
- React Flow rendering (icons/dagre/risk dots) is client-side; it compiles and the pages load,
  but pixel-level rendering was not screenshot-verified in this headless sandbox.
