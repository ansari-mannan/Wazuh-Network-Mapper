# Command: Rebuild SNMP topology discovery as a seed-based LLDP crawler

## What you are building

Rewrite the network-device topology discovery tool. The current version takes one or
more `--subnet` arguments and sweeps every address in the range with SNMP. Replace that
with a **seed-based LLDP crawl** that figures out the topology on its own, with no subnet
argument required. The output contract stays the same: a single JSON document on stdout
that the Node.js plugin layer consumes after spawning this script as a child process.

This tool discovers **network infrastructure only** — routers and switches reached via
SNMP/LLDP. It does not discover endpoints. Endpoints are handled by a separate Wazuh-agent
pipeline and must not be touched here.

## Why the approach is changing (read this before designing anything)

The old `--subnet 172.20.0.0/16` style of scan is the wrong shape for topology discovery:

- A /16 is 65,536 addresses. The overwhelming majority are empty, so the scan spends almost
  all of its time timing out on dead addresses to find a handful of switches.
- A single mistake — wrong interface, wrong VLAN, not actually connected to the target
  network — turns the entire run into 65k slow timeouts, and you don't find out for a long
  time. The failure is silent and slow.
- It is memory-hungry if implemented naively (see resource rules below).

LLDP gives us a better model. Every managed switch/router maintains a **neighbor table**
(LLDP-MIB) listing the devices directly cabled to it. So instead of guessing addresses, we:

1. Start from a **seed** device we can definitely reach.
2. Poll its LLDP neighbor table to learn its directly-connected neighbors.
3. Queue those neighbors, poll each of them, learn *their* neighbors, and repeat.
4. Stop when the queue drains (no new devices found).

This only ever touches real devices, terminates naturally, and fails **fast and loud** —
if the seed is unreachable you know after one timeout, not after grinding through an address
space. The work set is the real topology (tens to low hundreds of nodes), not the address
space, so the memory problem largely disappears on its own.

## Seeding (this is the one design decision that needs care)

The scanner host is an endpoint, not network gear, so "use my own IP" is not directly
usable — an IP isn't something you poll, you need a first *device*. Seed from, in priority
order:

1. **The default gateway.** It is a router or L3 switch, almost certainly speaks SNMP, and
   has a populated LLDP neighbor table. This is the primary, reliable seed. Detect it from
   the host routing table.
2. **The host's own LLDP neighbor**, if `lldpd` is running locally. This is literally "the
   switch this machine is plugged into" and is the most direct first hop. Use it as an
   additional seed when available.
3. **An explicit `--seed <ip>` override**, for cases where gateway detection fails or the
   operator wants to start somewhere specific.

Seed from all available sources; dedup happens naturally in the crawl.

## The hard walls — design around these, do not try to defeat them

These are real constraints. Handle them gracefully; do not paper over them.

1. **Credentials cannot be discovered.** The crawl finds *where* devices are; it does not
   find *how to authenticate* to them. SNMP community strings (v2c) or v3 user/auth/priv
   must be supplied by the operator. **Never brute-force community strings** — it is noisy
   and trips IPS/IDS. The tool may accept a small *operator-provided* set of communities to
   try per device, but only what the operator passes in. A device that responds to none of
   the supplied credentials is recorded as discovered-but-unpollable and the crawl moves on.

2. **The LLDP management-address gap.** A neighbor table entry tells you "device A connects
   to chassis X on port Y." To then poll X you need a routable management IP for it. LLDP
   *can* carry this in the remote management-address field but it is not guaranteed present
   or reachable. When a neighbor has no usable management address, record it as a known node
   (by chassis ID) and as an edge, but mark it unpollable and do not enqueue it.

3. **L3 reachability and segmentation.** LLDP is strictly link-local and never forwarded —
   each device only knows its direct neighbors. To poll each next device you must actually
   route to its management IP, which in real networks often lives on a separate management
   VLAN. If the scanner can't reach that VLAN, the crawl stops at that boundary. "Discover
   everything" honestly means "everything L3-reachable from the scanner." This is expected;
   surface it, don't crash on it.

4. **Dedup on chassis ID, not IP.** A device can appear under multiple IPs and be reached
   via multiple neighbors. Key the visited-set and the node map on **chassis ID** (the
   stable hardware identity), never on IP, or the crawl will loop and double-count. This is
   the same class of bug as a fragile hostname-based join — key on the hard identifier, not
   a soft one.

## Resource rules (low memory is a hard requirement)

The previous failure mode was a naive async fan-out that materialized one task per target up
front, so a concurrency cap throttled *execution* but not *allocation*. Do not repeat it.

- **Bounded worker pool over a queue.** Use a fixed set of worker coroutines (default ~32,
  configurable) pulling from an `asyncio.Queue` with a `maxsize` for backpressure. Do not
  `gather` over a pre-built list of all targets. Only a bounded number of work items should
  exist at any moment.
- **Reuse one SNMP engine.** Construct a single shared pysnmp `SnmpEngine` (or a tiny pool)
  for the whole run. Do **not** create an engine per target — the engine carries
  MIB/datastore state and is heavy.
- **Use GETBULK for table walks** (v2c+), not repeated GETNEXT, for the LLDP neighbor walk.
- **Tight timeouts, limited retries.** Most reachable devices answer fast; unreachable ones
  should fail quickly so a worker is freed, not held for many seconds.
- **A max-nodes safety cap** (default e.g. 5000, configurable) so a misconfigured or hostile
  environment can't cause an unbounded crawl.
- Accumulating the final node/edge maps in memory is fine here — the topology is small. The
  memory discipline is about the *in-flight crawl state*, not the result set.

## Module structure (clean, separate files, single responsibility each)

Do not put everything in one file. Suggested layout under a package directory:

- `__main__.py` — entry point. Thin: parse args, load config, run the crawl, emit output.
- `cli.py` — argument parsing and the CLI contract (see below).
- `config.py` — concurrency, timeouts, retry counts, max-nodes cap, credential loading from
  flags and environment variables. Keep all tunables here, not scattered.
- `models.py` — dataclasses for `Device` (node) and `Link` (edge), plus the credential
  representation. Node schema must align with the existing device schema used elsewhere in
  the project (see Output).
- `seed.py` — seed discovery: default gateway from the routing table, local `lldpd` neighbor
  if present, and the explicit `--seed` override.
- `snmp_client.py` — pysnmp wrapper. Owns the single shared engine. Exposes a `get(oid)` and
  a `walk(base_oid)` (GETBULK-backed), plus credential trial logic. All SNMP version detail
  lives here so nothing else imports pysnmp directly.
- `lldp.py` — pure parsing: turn raw LLDP-MIB walk results into neighbor records
  (chassis ID, remote port, remote management address). No I/O, no SNMP — just parsing, so
  it is trivially testable.
- `sysinfo.py` — fetch and parse `sysDescr.0` (and related scalars) into vendor / model /
  firmware fields for a node.
- `crawler.py` — the BFS crawl itself: the bounded worker pool, the queue with backpressure,
  the chassis-ID visited-set, enqueue/dequeue logic, and the unpollable/unreachable handling.
  This is the orchestration core.
- `output.py` — assemble the final node and edge maps into the output JSON and write it to
  **stdout only**.

Keep each file focused. `lldp.py` and `sysinfo.py` should be pure enough to unit-test without
a live network.

## CLI contract

The defining change: **no `--subnet`**. New invocation, roughly:

```
python -m <package> --community cyfor123 > output.json
```

- `--community` may be supplied multiple times to provide a set of operator-known strings to
  try. Also accept communities from an environment variable (consistent with how the other
  collectors in this project load credentials from the environment).
- `--seed <ip>` optional override for the seed device.
- `--concurrency`, `--timeout`, `--retries`, `--max-nodes` optional, all defaulting from
  `config.py`.
- Support v3 credentials (user/auth/priv) as an alternative to community strings.

## Output

- **stdout: JSON only.** The Node.js layer reads stdout to get the result, so a single valid
  JSON document is the entire stdout output.
- **stderr: all logging, progress, warnings, errors.** Nothing human-readable goes to stdout.
- Output structure: a list of **nodes** and a list of **edges**.
  - Each node aligns with the existing project device schema:
    `{ip, hostname, vendor, model, firmware, serial, mac, discovery_method, status}` with
    `discovery_method` set to `snmp_lldp`, plus a stable `chassis_id` carried through as the
    join key, and a `pollable` flag (false for discovered-but-unauthenticated or
    no-management-address neighbors).
  - Each edge is an adjacency `{source_chassis_id, target_chassis_id, local_port, remote_port}`.
- **Graceful degradation:** if the seed is unreachable or no devices are found, log the
  reason to stderr, emit a valid JSON document with empty node/edge lists, and exit cleanly
  (non-crashing). The downstream graph builder must always receive parseable JSON.

## Acceptance criteria

- Runs with no subnet argument and discovers reachable infrastructure starting from the
  gateway and/or local LLDP neighbor.
- An unreachable seed fails within roughly one timeout, not after a long sweep, with a clear
  stderr message and valid empty JSON on stdout.
- Memory stays flat and small across a crawl regardless of network size; in-flight work is
  bounded by the worker pool, not by the number of devices.
- The visited-set is keyed on chassis ID; a device reachable by multiple paths or IPs appears
  exactly once.
- Devices that respond to no supplied credential, or that have no usable management address,
  are recorded as nodes/edges with `pollable: false` and do not stall or crash the crawl.
- No community-string brute-forcing anywhere.
- stdout is valid JSON and nothing else; all diagnostics are on stderr.
- Endpoints are not discovered or included — infrastructure only.
- Code is split across the modules above with single, clear responsibilities per file.
