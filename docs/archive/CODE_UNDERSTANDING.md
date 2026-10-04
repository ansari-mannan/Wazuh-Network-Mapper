# Wazuh Network Mapper — Code Understanding

A plain-language tour of the whole codebase: what it does, how the pieces fit
together, and what each class/function is responsible for. The backend (the
Python scanner) is covered in the most depth, because that is where the real
work happens. The web app and the risk module are covered afterward.

---

## 1. The big picture (what is this thing?)

The project answers one question: **"What is on my network, how is it all wired
together, and which machines are vulnerable?"** — and then draws it as a clean
network diagram you can click through.

There are really **two programs** living in one repository:

1. **`vulnmapper/` — the Python scanner (the real backend).**
   It goes out onto a network, discovers every switch/router/firewall and every
   computer, figures out which device is plugged into which switch port, pulls
   the list of known security vulnerabilities (CVEs) for each computer, and
   merges all of that into **one big JSON file** called `graph.json`. This is
   the heart of the project.

2. **The web app (Next.js + React, in `app/`, `lib/`, `risk-module/`).**
   A browser dashboard that reads `graph.json` and draws it. It can also press a
   button to *re-run* the Python scanner. Most of the dashboard screens are
   demo/mock screens; only the **Topology Map** and **Asset Detail** screens are
   wired to the real scanner output.

The two halves talk through a single contract: the **graph document**, a JSON
object shaped like `{ nodes, edges, metadata }`. If you understand that shape,
you understand how the whole system communicates.

```
   NETWORK LAB                         FILE                       BROWSER
 ┌─────────────┐   python -m       ┌────────────┐   /api/graph  ┌──────────┐
 │ Wazuh + SNMP│ ── vulnmapper ──▶ │ graph.json │ ───────────▶  │ React UI │
 │  switches…  │                   │ {nodes,    │               │ topology │
 └─────────────┘ ◀── /api/scan ─── │  edges,    │ ◀── click ─── │  diagram │
                  (re-run scanner)  │  metadata} │               └──────────┘
                                    └────────────┘
```

---

## 2. The shared vocabulary: the graph document

Everything centers on these three concepts. (Defined in
[vulnmapper/common/schema.py](vulnmapper/common/schema.py).)

- **Node** — one *thing* on the network. Two flavors:
  - **endpoint** — a computer/server running a Wazuh agent (a piece of
    monitoring software). These are the things that have *vulnerabilities*.
  - **device** — network infrastructure: a switch, router, or firewall, found by
    talking to it over SNMP/LLDP.
- **Edge** — a *connection* between two nodes. Two flavors:
  - **lldp** — a cable between two infrastructure devices (switch ↔ router).
  - **endpoint_link** — a computer hanging off a specific switch port.
- **metadata** — counts, timing, and bookkeeping about the scan itself.

### Every node has a stable ID

The single most important design decision: **never identify a node by its
hostname or IP address**, because those are soft (they change, they collide, the
same name can mean two machines). Instead every node gets a hard, unique
`node_id` with a prefix that tells you its type at a glance:

- `endpoint:<agent_id>` — a Wazuh-monitored computer (keyed by its agent ID).
- `device:<chassis_id>` — an infrastructure device (keyed by its hardware chassis ID).
- `host:<mac>` — a computer found *only* in a switch's memory tables, with no
  agent (keyed by its MAC address).

`node_id`, `kind`, `Node`, `Edge`, and `CVE` are the building blocks; the helper
functions `endpoint_node_id()`, `device_node_id()`, and `host_node_id()` just
build those prefixed strings.

The `Node` dataclass is a **superset** of both flavors' fields. A field that
doesn't apply (e.g. `top_cves` on a switch) simply stays empty. The `to_dict()`
method emits a clean, ordered JSON shape and only includes the fields relevant to
the node's kind.

---

## 3. The Python scanner — the backend in depth

The package is `vulnmapper/`. You run it like this:

```
python -m vulnmapper --community REDACTED_COMMUNITY > graph.json
```

It prints the finished graph document to **stdout** (and only that), while all
log/progress messages go to **stderr**. That clean separation is deliberate: the
web app captures stdout to get the result, uncontaminated by log noise.

### 3.1 The conductor: `pipeline.py`

[vulnmapper/pipeline.py](vulnmapper/pipeline.py) is the top-level orchestrator.
Think of it as a conductor that runs four movements in order and times each one:

```
   collect  ─▶  score   ─▶   crawl    ─▶  assemble  ─▶  graph.json
 (find PCs)  (find CVEs)  (map network)  (merge it)
```

Key functions:

- **`build_parser()`** — defines the command-line options. The interesting ones
  let you *skip* live work and feed cached files instead:
  - `--scored PATH` — use a saved endpoints file (skip the live Wazuh stages).
  - `--network PATH` — use a saved network topology (skip the live SNMP crawl).
  - `--no-endpoints` / `--no-network` — build a one-sided graph.
  - `--community` / `--seed` — credentials and starting points for a live crawl.

  This is how you rebuild `graph.json` at home (no lab access) from previously
  captured data.

- **`_load_endpoints()`** — returns the list of scored computers. If skipped, it
  returns nothing; if cached, it reads the file; otherwise it runs the live
  **collect → score** stages against Wazuh.

- **`_load_network()`** — returns the network topology dict. Same pattern: skip,
  cache, or run the live SNMP/LLDP crawl.

- **`run()`** — the entry point. It records timing with a *monotonic clock* (so
  the durations are correct even if the system clock jumps), loads endpoints and
  network, calls `assemble()` to merge them, stamps the metadata with timing and
  counts, and writes the result. A skipped phase's duration stays `null` (which
  honestly means "did not run", not "ran instantly").

A guiding principle throughout: **every stage tolerates per-item failures and
the run always produces a valid document.** One broken device never aborts the
scan.

---

### 3.2 The endpoint side: finding computers and their vulnerabilities

This track answers: *which computers exist, and what's wrong with them?* It talks
to two Wazuh services. Code lives in `vulnmapper/endpoints/`.

There's a clean three-layer split repeated here:

- **Fetch layer** — only does HTTP, no logic.
- **Normalize layer** — only reshapes data, no I/O.
- **Orchestration layer** — ties them together, tolerates failures.

#### Collecting the inventory (`collect.py` + `wazuh_client.py`)

- **`WazuhClient`** ([wazuh_client.py](vulnmapper/endpoints/wazuh_client.py)) is
  the *fetch layer* for the Wazuh **Manager API** (port 55000). It logs in
  (`authenticate()`), then exposes raw getters: `get_agents()` (the list of all
  monitored computers) and three "syscollector" calls per agent —
  `get_netiface()` (network cards), `get_netaddr()` (IP addresses),
  `get_hardware()` (serial number). No business logic, just HTTP.

- **`collect_agents()`** ([collect.py](vulnmapper/endpoints/collect.py)) is the
  *orchestrator*: authenticate, loop over every agent (skipping agent `000`,
  which is the manager itself, not a real endpoint), fetch its hardware/network
  data, and hand it to the normalizer. If one agent's data fails to load, it
  logs the problem and moves on with empty data instead of crashing.

#### Reshaping raw data into clean nodes (`normalize.py`)

[normalize.py](vulnmapper/endpoints/normalize.py) is pure data-shaping — the
fiddly part of turning messy real-world data into clean fields.

- **`select_mac()`** is the clever bit. A computer reports *many* network
  interfaces — real NICs, but also VMware adapters, loopback, Hyper-V, VPN, etc.
  We must pick the one *real physical MAC address*, because that MAC is later
  matched against switch memory tables to figure out which port the machine is
  on. It:
  1. throws away virtual/software interfaces (`is_physical_iface()`),
  2. throws away interfaces with a "locally-administered" MAC
     (`is_locally_administered()` — virtual adapters set a specific bit that
     real burned-in NIC addresses don't),
  3. throws away interfaces with no real IPv4 address (APIPA `169.254.*`
     addresses are dropped),
  4. and from what's left, prefers the interface whose IP matches the agent's
     known IP, then one that's "up", then just the first.

- **`normalize_agent()`** maps a raw agent + its hardware into the shared node
  dict (`agent_id`, `ip`, `hostname`, `vendor`, `model`, etc.). The `agent_id`
  is carried through because it's the *hard join key* used in the next stage.

- **`parse_hit()`** flattens one raw vulnerability document (from OpenSearch)
  into a tidy CVE dict.

- **`enrich_agent()`** attaches the CVE list to an agent and computes its
  `risk_score` — simply the **highest CVSS score** among its CVEs (the CVEs
  arrive pre-sorted worst-first, so it just reads index 0).

#### Scoring vulnerabilities (`score.py` + `indexer_client.py`)

- **`IndexerClient`** ([indexer_client.py](vulnmapper/endpoints/indexer_client.py))
  is the *fetch layer* for the Wazuh **Indexer** (OpenSearch, port 9200). Its one
  method, **`top_cves(agent_id, k=3)`**, asks the vulnerability database for an
  agent's top 3 worst CVEs, sorted by CVSS descending. Crucially it filters on
  `agent.id` (the hard key), not `agent.name` — keying on the soft name was a
  known source of mismatches.

- **`score_agents()`** ([score.py](vulnmapper/endpoints/score.py)) loops over
  every collected agent, fetches its top CVEs, and enriches it. Per-agent query
  failures are caught and logged; that agent just ends up with zero CVEs.

**End result of the endpoint track:** a list of computer dicts, each with
identity, a physical MAC, a `risk_score`, and its top CVEs.

---

### 3.3 The network side: mapping the infrastructure

This track answers: *what switches/routers exist, how are they cabled, and what
MAC addresses live on which port?* It's the most involved part of the codebase.
Code lives in `vulnmapper/network/`.

The core idea is a **seed-based crawl**: start at one known device (the
gateway), ask it "who are your neighbors?", then visit each neighbor and repeat —
like exploring a maze room by room. It only ever touches *real devices* it has
been told about, so it always terminates and never blindly scans an address
range.

#### Where to start: `seed.py`

The scanner runs *on* a computer, which isn't network gear, so it needs a first
real device to talk to. [seed.py](vulnmapper/network/seed.py) finds one:

- **`default_gateways()`** reads the host's routing table to find the default
  gateway (your router). On Windows it uses PowerShell and deliberately filters
  out *virtual* adapter gateways (VMware, Hyper-V, VirtualBox) so the crawl
  doesn't waste time on a dead virtual gateway. On Linux/macOS it parses
  `ip route` / `netstat`.
- **`local_lldp_neighbors()`** asks the local LLDP daemon (if any) what switch
  this machine is plugged into.
- **`discover_seeds()`** merges explicit `--seed` overrides, gateways, and LLDP
  neighbors into a de-duplicated starting list.

Every helper here swallows its own errors — a missing tool yields *no seed*,
never a crash.

#### Talking SNMP: `snmp_client.py`

[snmp_client.py](vulnmapper/network/snmp_client.py) is the **only** file that
imports the SNMP library (pysnmp). It hides all the async/protocol ugliness
behind a small surface:

- **`resolve_credential(ip)`** — tries each operator-supplied community
  string/credential *once* against a device and remembers the first that works.
  This is "trying the keys the operator gave us", explicitly **not** brute-forcing.
- **`get_many()` / `get()`** — read specific values (OIDs) from a device.
- **`walk()`** — read a whole table from a device (using GETBULK).
- **`walk_vlan_context()`** — a special trick for Cisco gear: to read a specific
  VLAN's forwarding table over SNMPv2c you must suffix the community string with
  `@<vlan-id>` (e.g. `REDACTED_COMMUNITY@10`). This method builds that contextual community.

One detail worth knowing: a **single shared SNMP engine** is reused for the
whole crawl (it's heavy to build), which is safe because the crawl is a small
bounded worker pool, not a wide sweep.

`Credential` (in [models.py](vulnmapper/network/models.py)) holds one credential
to *try*, with a secret-free `label` for logs so community strings never leak
into log files.

#### The crawl engine: `crawler.py`

[crawler.py](vulnmapper/network/crawler.py) is the BFS (breadth-first) explorer.
The **`Crawler`** class owns all the shared state and a pool of worker
coroutines.

How it works:

- A fixed number of workers (default 32) pull "next-hop" jobs `(ip, chassis_id)`
  off an `asyncio.Queue`. At most 32 devices are ever being polled at once, so
  memory stays bounded no matter how big the network is.
- **Dedup is keyed on chassis ID, never IP.** A device reachable through several
  neighbors or several IPs is still polled exactly once. `_enqueue()` enforces
  this plus a `max_nodes` safety cap.
- **`seed()`** loads the initial seed IPs into the queue.
- **`run()`** starts the workers, waits for the queue to drain, then tells each
  worker to stop (via a sentinel) and returns the collected devices + links.
- **`_worker()`** is the loop each worker runs: pull a job, process it, mark it
  done. A failure on one device is caught so it never kills the worker.
- **`_process(ip)`** is the per-device routine, and it's the meatiest:
  1. resolve a working credential (if none, record the device as
     *unreachable* and stop).
  2. fetch its identity (`sysinfo.fetch`).
  3. walk its LLDP neighbor table (`_walk_neighbors`).
  4. split the local ports into **`neighbor_ports`** (every port with *any* LLDP
     neighbor) and **`uplink_ports`** (only ports whose neighbor is itself
     *infrastructure* — a switch/router — not an end host). This distinction is
     critical for later port-matching: only true uplinks get subtracted when
     deciding which port a host sits on.
  5. collect the device's forwarding table, ARP table, own MAC addresses, and
     per-port up/down status.
  6. record an edge to each neighbor, and *enqueue* any neighbor that has a
     management IP (so it can be polled too) — `_handle_neighbor()`.

A subtle touch: a device's **own advertised LLDP capabilities** (what it says it
is) are the most reliable signal of its role and win over what a neighbor
reported about it; that fallback is applied in `run()` once all devices exist.

#### Parsing LLDP neighbor tables: `lldp.py`

[lldp.py](vulnmapper/network/lldp.py) is **pure parsing** — it turns raw
`(oid, value)` table rows into tidy `Neighbor` records, with no network access,
so it's easily unit-tested.

Three SNMP tables feed one neighbor record, all joined on the same
`(localPort, remoteIndex)` key:

- **`parse_rem_table()`** — the neighbor's chassis ID, port, name, description,
  and capability bitmaps.
- **`parse_man_addr_table()`** — the neighbor's management IP. The clever part:
  the IP is encoded *inside the OID index itself*, not in the value, so this
  function digs the address bytes out of the OID arcs (preferring IPv4).
- **`parse_loc_port_table()`** — translates our local port *number* into a
  human-readable port name like `Gi0/3`.
- **`build_neighbors()`** combines all three into a list of `Neighbor` objects.

#### Identifying a device: `sysinfo.py` + `vendors/`

[sysinfo.py](vulnmapper/network/sysinfo.py)'s **`fetch()`** reads a device's
basic identity scalars (description, object ID, name, chassis ID, capabilities)
in one request, figures out the vendor from the SNMP "enterprise number", and
hands off to a **vendor plug-in** for model/firmware/serial.

- **`enterprise_number()`** pulls the vendor's number out of the sysObjectID.
- **`vendor_from_descr()`** is a best-effort text guess for devices we can't
  poll fully.

The vendor plug-ins live in `vulnmapper/network/vendors/` and each exposes one
`identify()` coroutine:

- **`cisco.py`** — Cisco's description text is rich, so model and IOS version are
  pulled straight out of it with regex (no extra queries).
- **`fortinet.py`** — FortiGate's description is *empty*, so it must ask SNMP
  directly: model comes from a lookup table (`fortinet_models.json`), firmware
  and serial from specific Fortinet OIDs.
- **`__init__.py`** maps enterprise number → (vendor name, module). To support a
  new vendor you drop in a module and register its number here.

A deliberate philosophy: **roles are never guessed from the vendor.** "It's a
Fortinet, so it must be a firewall" is an inference, not evidence — the code
refuses to do that.

#### Reading switch memory: `fdb.py` + `fdb_collect.py`

This is how the scanner learns *which port a computer is plugged into*. A switch
keeps a **forwarding database (FDB)**: a table of "I last saw MAC address X on
port Y". Match a computer's MAC against that table and you know its port.

- **`fdb_collect.py`** is the thin I/O orchestration (`collect_fdb`,
  `collect_arp`, `collect_own_macs`, `collect_port_status`). For Cisco gear it
  does the per-VLAN `community@vlan` dance: enumerate the VLANs, then walk each
  VLAN's forwarding table in its own context. For everything else it falls back
  to a single default read. Every walk is best-effort — an unsupported table
  yields an empty result, not a failure.
- **`fdb.py`** is the **pure parser** behind it. Switches report ports as opaque
  "bridge port" numbers, so it chains several lookups to translate them into real
  names: `bridge-port → ifIndex → ifName` (e.g. `Gi0/3`). Notable functions:
  - `parse_dot1q_fdb()` / `parse_dot1d_fdb()` — decode the two FDB table formats
    (the MAC is buried in the OID as dotted-decimal octets and reassembled).
  - `parse_arp()` — IP↔MAC mappings (lets us attach an IP to a discovered host).
  - `parse_own_macs()` — the device's *own* interface MACs, so a router's gateway
    MACs don't get mistaken for separate "host" devices later.
  - `build_port_status()` — `{port_name: "up"/"down"}` for every interface.
  - `parse_vtp_vlans()` — the list of operational VLANs to walk.

#### Bundling the network output: `output.py` + `models.py`

- **`Device`** and **`Link`** ([models.py](vulnmapper/network/models.py)) are the
  network track's data records. `Device.to_node()` renders one in the output
  shape. The comments stress not to conflate the three port concepts
  (`neighbor_ports`, `uplink_ports`, `port_status`).
- **`output.build_document()`** ([output.py](vulnmapper/network/output.py))
  assembles the final `{nodes, edges}` for the network side. Its key helper
  **`_dedupe_edges()`** collapses the two directions of each cable (A sees B, B
  sees A) into a single edge, keeping the best port label from either end.

#### Configuration: `config.py` + `cli.py`

- **`config.py`** holds every tunable (concurrency, timeout, retries, max_nodes,
  port) in one place and loads SNMP credentials from CLI flags + environment
  variables. There's a baked-in lab community (`REDACTED_COMMUNITY`) used only as a last
  resort.
- **`cli.py`** defines the standalone command line for the crawler. The headline
  difference from older tools: there is **no `--subnet`** — the crawl seeds and
  discovers itself.

#### Running it: `runner.py`

[runner.py](vulnmapper/network/runner.py) is the programmatic entry point shared
by both the CLI and the pipeline. **`crawl_document(cfg)`** is the synchronous
wrapper everyone calls; it runs the async crawl and *always* returns a valid
document (an empty one if the crawl blows up).

---

### 3.4 The merge: where the two worlds become one graph

This is the cleverest module: [vulnmapper/assemble/merge.py](vulnmapper/assemble/merge.py),
with help from [vulnmapper/linking/fdb_link.py](vulnmapper/linking/fdb_link.py).
It takes the list of computers (endpoints) and the network topology and answers
the hard question: **which switch port is each computer plugged into?**

It does this with a **three-tier "parenting ladder"** — it tries the strongest
evidence first and falls back to weaker evidence. The tier that succeeds is
recorded as the edge's `confidence`, so the output is honest about how sure it is.

> **Tier 1 — LLDP match (strongest).** If a computer also speaks LLDP, the switch
> already reported it as a neighbor with the *exact* port. In this case the LLDP
> crawl created a "phantom" device node for that computer (it looked like a
> device from the switch's view). The merge detects this — the phantom's chassis
> ID equals the computer's MAC — **merges the two into one node**, deletes the
> phantom, and parents the computer to its switch on the known port. Confidence:
> `lldp`.

> **Tier 2 — FDB match (medium).** For an online computer that *doesn't* speak
> LLDP, look its MAC up in the switch forwarding tables. To avoid placing it on
> every switch along the path, the *uplink ports* are subtracted so the MAC lands
> on the actual *access* switch it's connected to. If a MAC appears on several
> candidate ports, the tie-break picks the port with the *fewest* MACs (an access
> port has one host; a trunk has many). Confidence: `resolved` or `tiebreak`.

> **Tier 3 — subnet fallback (weakest).** For an offline computer (no live FDB
> entry) or one with no MAC at all, just parent it to a device that shares its
> `/24` subnet, preferring a real pollable switch/router. Confidence:
> `subnet_fallback`. If even that fails, the computer is left *unparented* with
> an honest recorded reason (no MAC / offline / absent from all tables).

#### The linking helper: `fdb_link.py`

This module builds and queries the **MAC lookup table** that Tier 2 needs. It's
pure (no I/O), so it's fully unit-testable.

- **`build_mac_table()`** walks every switch's FDB, drops the switch's own MACs
  and uplink/trunk ports, and produces a `MacTable`: `mac → HostFact` (where a
  MAC lives: which switch, which port, which VLAN, how confident), plus a `by_ip`
  index and an `infra_macs` exclusion set.
- **`_infra_macs()`** gathers the infrastructure's own MAC addresses so a
  router's gateway MACs never get mistaken for separate hosts.
- **`same_subnet()`** is the simple Tier-3 check: do two IPs share a `/24`?
- It also defines the `CONF_*` confidence constants and the `REASON_*`
  unparented-reason strings.

#### Deriving roles: `roles.py`

[roles.py](vulnmapper/network/roles.py) decides *what a node is* (its `role`),
strictly from the LLDP **system-capabilities bitmap** the device advertised —
again, no vendor guessing.

- **`decode_capabilities()`** turns the raw bitmap into a set of names
  (`bridge`, `router`, `station`, etc.).
- **`role_from_capabilities()`** maps that set to a role:
  `router + bridge → l3-switch`, `bridge → l2-switch`, `router → router`,
  `station → station`, and so on.
- **`derive_role()`** is the public entry: capabilities first, else a sensible
  fallback (`host` for computers, `Unknown Network Device` for polled gear that
  advertised nothing).
- **`neighbor_is_infrastructure()`** is what the crawler uses for the
  uplink-vs-access-port split: a neighbor with a management IP, or one
  advertising a bridge/router/AP capability, is infrastructure (an uplink);
  a bare station/phone is an end host (an access port).

#### Walking through `assemble()` step by step

The single function `assemble(endpoints, network_doc)` runs the whole merge:

1. Build `device` nodes from the network doc and `endpoint` nodes from the
   scored computers; index endpoints by MAC.
2. **Tier 1:** find phantom device nodes whose chassis ID matches an endpoint's
   MAC, parent that endpoint to its reporting switch, and delete the phantom.
3. Build the **LLDP edges** between surviving devices.
4. **Tiers 2 & 3:** for every still-unparented endpoint, try the FDB table, then
   the subnet fallback; record an unparented reason if both fail. (A nice extra:
   if Wazuh gave no MAC but the switch's ARP table knows the endpoint's IP, the
   MAC is *back-filled* from the table.)
5. **FDB host discovery:** any MAC sitting in a switch table that matches *no*
   known node becomes a brand-new `host:` node — a computer with no agent,
   discovered purely from switch memory (status `discovered`, `risk_score` null
   because it's unscored).
6. Build the **endpoint edges** from the parenting results.
7. **Discovery stamping:** order the nodes so the frontend can "replay" discovery
   as a growing graph — devices first in BFS order from the seed
   (`_bfs_device_order()`), then each device's attached endpoints right after it.
   Each node gets a `discovery_order` and a `parent_id`.
8. Add readable `source_name`/`target_name` to every edge.
9. Assemble **metadata**: counts, confidence breakdown, lists of unparented
   endpoints (with reasons) and unreachable boundary devices.

The return value is the complete `{nodes, edges, metadata}` document — exactly
the contract the web app consumes.

---

### 3.5 Shared utilities

- **`common/mac.py`** — *the* single source of truth for MAC addresses. Two
  worlds report MACs in wildly different formats (`e4:a7:a0:25:ce:ad`,
  `"E4 A7 A0 25 CE AD"`, `0xe4a7...`, raw bytes). If they aren't normalized
  identically, every FDB match silently fails. `canonical_mac()` returns the bare
  comparison form; `format_mac()` returns the pretty colon form.
- **`common/config.py`** — env-var loading + TLS settings for the *endpoint*
  (Wazuh) side. TLS verification is off by default (the lab uses self-signed
  certs) but can be turned on via an env var without code changes. Contains
  baked-in lab credentials for convenience (flagged clearly as not for prod).
- **`common/schema.py`** — the `Node`/`Edge`/`CVE` definitions and ID helpers
  (covered in §2).
- **`network/utils.py`** — chassis-ID and whitespace normalization, built on top
  of the shared MAC canonicalizer so a device's own chassis ID and a neighbor's
  reported chassis ID line up exactly.

### 3.6 Tests

`tests/` holds focused unit tests for the pure modules — MAC handling, FDB
parsing, LLDP-to-link decoding, role derivation, and the assemble merge. Because
the parsing and merging logic is deliberately I/O-free, these run with no network.

---

## 4. The web app — serving and drawing the graph

A **Next.js** app (React 19, App Router). It has a tiny backend (API routes) and
a React frontend.

### 4.1 The API routes (the web backend) — `app/api/`

These are thin server endpoints. They are the *only* way the browser touches the
graph or the scanner; the browser never reads files directly.

- **`GET /api/graph`** ([app/api/graph/route.ts](app/api/graph/route.ts)) —
  reads `graph.json` **fresh from disk** every time and returns it. The graph is
  never bundled into the frontend, so the file the scanner writes is always the
  single source of truth. Returns clean 404/500 errors if the file is missing or
  corrupt.

- **`POST /api/scan`** ([app/api/scan/route.ts](app/api/scan/route.ts)) —
  re-runs the Python scanner. It `spawn`s `python -m vulnmapper --community
  <value>`, captures its stdout, validates that the output is real JSON, and only
  then overwrites `graph.json` (so a failed scan never destroys a good file). The
  work runs **asynchronously**: the route immediately replies `202 running`, and
  the UI polls for completion. Errors (e.g. no lab access from home) are caught
  and surfaced, never crash the server. Arguments are passed as an array (no
  shell), so the community string can't inject a second command.

- **`GET /api/scan/status`** ([app/api/scan/status/route.ts](app/api/scan/status/route.ts))
  — returns the current scan state (`idle`/`running`/`done`/`error`).

- **`GET /api/config`** ([app/api/config/route.ts](app/api/config/route.ts)) —
  returns the default community string (`REDACTED_COMMUNITY`) to pre-fill the input.

- **`lib/scanState.ts`** — a tiny module holding the shared scan state in a
  module-level variable, so the `/api/scan` writer and the `/api/scan/status`
  reader see the same object. (A real deployment would key this by job ID; for a
  one-scan-at-a-time tool a single object is enough.)

### 4.2 The frontend client — `lib/vulnmapperApi.ts`

The browser's typed client for those routes: `getGraph()`, `startScan()`,
`getScanStatus()`, `getConfig()`, plus the TypeScript types (`GraphNode`,
`GraphEdge`, `Metadata`, …) that mirror the Python output shape. Its `asJson`
helper throws on non-2xx responses with the server's error message.

### 4.3 Drawing the topology — `risk-module/ui/poc/`

The pieces that turn the graph into the clickable diagram (the task spec called
out three of these specifically):

- **`layout.ts` → `layoutGraph()`** — React Flow does **not** auto-position
  nodes, so this runs **dagre** to compute a top-down hierarchy. The hierarchy
  edges fed to dagre come from each node's `parent_id` (root = the node with
  `parent_id === null`, i.e. the top switch), *not* the raw edges (an
  endpoint_link points child→parent, the wrong way for a top-down tree). Every
  node is added so unparented endpoints spread across the top instead of stacking
  at the origin. Returns `{id, x, y, data}` with React-Flow top-left coordinates.

- **`icons.ts` → `iconForRole()`** — maps a role to a clean lucide icon:
  switches → network glyph, router → router, firewall → shield, host/station →
  monitor, server → server, unknown → generic box. (Deliberately MIT-licensed
  icons, not Cisco's proprietary art.)

- **`nodeStyle.ts`** — the subtle risk indicator. `riskColor()` returns a small
  dot color: **≥9 red, 7–9 orange, >0 yellow, ==0 green, and `null` GREY** — the
  important rule being that *unscored* (null) is grey, **never green**, because
  green means "scored and clean". `isOffline()` flags `disconnected`/`discovered`
  nodes so they can be dimmed/dashed.

- **`PocTopologyView.tsx`** — the React Flow canvas: lays out the nodes, draws
  LLDP edges solid and endpoint links dashed, labels ports, and calls back when a
  node is clicked.

- **`CustomNode.tsx` / `PocDeviceDetail.tsx`** — the node rendering and the
  device-detail panel (identity block, CVE list for computers, port up/down grid
  for switches).

### 4.4 The dashboard screens — `app/dashboard/` + `risk-module/ui/screens/`

The dashboard layout ([app/dashboard/layout.tsx](app/dashboard/layout.tsx))
provides the sidebar nav and light/dark toggle. Each route renders a screen
component. Two important truths about these screens:

- **Wired to the REAL scanner:**
  - **Topology Map** ([TopologyMap.tsx](risk-module/ui/screens/TopologyMap.tsx)) —
    loads `/api/graph`, draws it, and hosts the **Run New Scan** button (calls
    `/api/scan`, polls status, reloads on success, and on failure keeps the
    current graph on screen).
  - **Asset Detail** ([AssetDetail.tsx](risk-module/ui/screens/AssetDetail.tsx)) —
    looks up one node by `node_id` in the real graph and shows its full detail.
    (Node IDs contain colons, so they're URL-encoded in the link and decoded here.)

- **Demo/mock screens:** Risk Dashboard, Vulnerability Report, Recommendations,
  Executive Report, etc. display **hardcoded sample data**. Their comments
  explicitly say they're "de-functionalized" — buttons render but don't act. They
  exist to show the intended product shape, not to reflect live scan results.

---

## 5. The risk module — a separate (mostly mock) scoring system

`risk-module/` (outside the `ui/` folder) is a self-contained, layered demo of a
*risk-scoring* system. It is **not** connected to the Python scanner's real
data — it reads mock JSON files. It's best understood as a parallel MVP that
shows how risk *would* be calculated.

Its layers:

- **`data-layer/dataLoader.ts`** — loads three mock JSON files
  (`mockAssets.json`, `mockVulnerabilities.json`, `topologyDefinition.json`) and
  exposes `getAssets()`, `getVulnerabilities()`, `getTopology()`.

- **`risk-engine/`** — the pure scoring math:
  - `aggregation.ts` → `aggregateTopVulnerabilities()` averages an asset's top-N
    CVSS scores.
  - `exposureMultiplier.ts` → internet-facing assets count 1.5×, internal 1.0×,
    restricted 0.8×.
  - `assetCriticality.ts` → critical assets weigh 1.5× down to low 0.8×.
  - The headline formula: **risk = (avg of top CVSS) × exposure × criticality**.
  - (`riskCalculator.ts` is a stubbed placeholder returning 0.)

- **`topology-engine/`** — `exposureClassifier.ts` buckets an asset as
  internet-facing/internal/restricted from free text;
  `topologyAnalyzer.ts`/`lateralMovementAnalyzer.ts` are stubs.

- **`api-layer/riskService.ts`** — the single façade the demo UI calls. It
  combines the data + engines into ready-to-render results:
  `getDashboardSummary()`, `getAssetsWithRisk()`, `getVulnerabilityReport()`,
  `getRecommendations()`, `getExecutiveReport()`, and `getAttackPathAnalysis()`.
  The attack-path function is the most interesting: it does a depth-first search
  from internet-facing assets through the topology edges to enumerate possible
  intrusion paths, scoring each by the summed risk of the hops.

Only three screens actually use this service (TopologyLegend, AttackPathAnalysis,
ScanConfiguration); the rest of the dashboard uses inline hardcoded data.

---

## 6. How a full run flows, end to end

Putting it all together, here is the life of one scan:

1. **User clicks "Run New Scan"** in the Topology Map screen.
2. The browser POSTs to **`/api/scan`**, which spawns
   `python -m vulnmapper --community REDACTED_COMMUNITY` and replies `202 running`.
3. **`pipeline.run()`** orchestrates four stages:
   - **collect** — `WazuhClient` + `collect_agents()` pull every monitored
     computer; `normalize_agent()` cleans each one and picks its real MAC.
   - **score** — `IndexerClient.top_cves()` + `score_agents()` attach each
     computer's worst CVEs and a risk score.
   - **crawl** — `seed.discover_seeds()` finds a starting device; `Crawler` does
     a BFS over SNMP/LLDP, learning every switch/router, its neighbors, its
     forwarding tables, and its port states.
   - **assemble** — `assemble()` merges computers into the topology using the
     three-tier parenting ladder, discovers extra hosts from switch memory,
     stamps roles and discovery order, and emits `{nodes, edges, metadata}`.
4. The pipeline prints that JSON to **stdout**. The API route validates it and
   overwrites **`graph.json`**, then flips the scan status to `done`.
5. The browser, which has been **polling `/api/scan/status`**, sees `done`, calls
   **`/api/graph`** to fetch the new file, runs **dagre** to lay it out, and
   re-renders the diagram with role icons, risk dots, and up/down ports.
6. Clicking any node opens **Asset Detail** for that exact `node_id`.

If anything fails (no lab access from home, a dead device, a missing MIB), the
failure is caught at its layer, logged, and the run still produces a valid
graph — the system degrades gracefully rather than crashing.

---

## 7. Recurring design principles (the "why" behind the code)

A few ideas show up everywhere; knowing them makes the whole codebase read more
easily:

- **Hard keys over soft keys.** Identify things by agent ID / chassis ID / MAC,
  never by hostname or IP, which collide and drift.
- **Evidence over guessing.** Roles come from what a device *advertised*, not
  from "it's brand X so it's probably a firewall." Uncertainty is labeled
  honestly (`confidence`, unparented `reason`, `Unknown Network Device`).
- **Fail soft, always emit.** Every stage tolerates per-item failures; the run
  always produces a valid document.
- **Pure core, thin I/O shell.** Parsing/merging logic is separated from network
  and file I/O, so the hard logic is unit-testable without a live lab.
- **One canonical form.** MACs (and chassis IDs) are normalized through a single
  function so the two data worlds can actually be compared.
- **stdout is the result, stderr is the noise.** A clean machine-readable result
  on stdout; all logging on stderr.
