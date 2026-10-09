# vulnmapper (backend)

`vulnmapper` is the Python scanner. It collects endpoints and their CVEs from
Wazuh (Manager API and Indexer), crawls the network over SNMP/LLDP from a seed
device, and merges both into one graph document with `nodes`, `edges` and
`metadata`.

## Layout

- `vulnmapper/`: the scanner package (`python -m vulnmapper`).
- `tests/`: unit tests, golden files and fixtures.
- `scripts/`: maintenance scripts (`_freeze_golden.py` refreshes the golden
  files; `verify_comware.py` checks an HP Comware switch over SNMP;
  `captures.py` turns raw SNMP captures into test fixtures;
  `checklist_sample_graph.py` puts configuration checks from captures into a
  graph; `hosts_sample_graph.py` labels the hosts of an existing graph;
  `build_oui.py` rebuilds the MAC manufacturer registry).
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
- `--no-device-cves`, `--nvd-cache PATH`, `--nvd-budget SECONDS`: the device
  CVE stage (see "Device CVEs").
- `--no-checklist`, `--check-default-communities`, `--check-management-ports`:
  the configuration checks (see "Configuration checks").
- `--no-name-lookup`, `--probe-unmanaged-snmp`: hosts without an agent (see
  "Unmanaged hosts").
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

### Device identity

Every polled device has the standard inventory table (ENTITY-MIB
`entPhysicalTable`) read, whatever its vendor: the chassis entry's model name
and serial number (the first member of a stack). Only the first page of two
columns is read, two requests per device (three for a table without a class
column). The model becomes the exact product name ("WS-C3750-48TS-S" instead
of the image family "C3750"); a FortiGate keeps Fortinet's own model and serial,
and a Comware switch its model table's name. A missing serial is filled. A
device without the table loses nothing.

A device is named by its LLDP chassis id. One without (e.g. an access point
that speaks only CDP) is named by its base MAC: of its own globally
administered interface MACs, the one the most interfaces share, a tie going to
the lowest. `device:ip:<address>` is used only when no MAC can be read at all.
A device first reached through a CDP neighbour entry has `discovery_method:
"snmp_cdp"`; seeds and LLDP-reached devices keep `"snmp_lldp"`. A device whose
software family is recognised carries `software_family` (see "Device CVEs").

### CDP and access points

The crawl follows CDP neighbours as well as LLDP ones (Cisco `cdpCacheTable`;
a device without CDP costs one request). A neighbour seen over both is one
device and one link; a link only CDP reported carries `"protocol": "cdp"`.
Only a CDP neighbour with router or switch capability makes its port an
uplink, so the hosts behind a phone or an access point stay visible.

A polled device that answers the Cisco wireless association MIB (or, failing
that, whose CDP platform or system description names an access point) gets
the role `access-point`. Its clients are read from its association table
(MAC, and IP, SSID, radio where provided); its bridge table is not used.

- A host or endpoint in an access point's client list is placed under it
  (confidence `wifi`, the radio as the port) with `"wifi": {ssid,
  access_point, radio}` on its node, replacing a switch-table or subnet
  placement. A client nothing else knows becomes a host with
  `discovery_method: "snmp_wifi"`.
- The access point sits on the switch port its CDP link names, with
  `"wifi_clients": <count>` on its node.
- A host learned from a switch's forwarding table carries the `"vlan"` it was
  learned on.

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
  "metadata": {"scan_time": "...",
               "counts": {"hosts": 0, "devices": 0, "cves": 0, "findings": 0}},
  "cves":  {"<CVE id>": {"cvss", "cvss_version", "severity", "description",
                         "reference", "published_at"}},
  "hosts": {"<node_id>": {"kind": "endpoint", "hostname", "agent_id",
                          "findings": [{"cve", "package", "version", "detected_at"}]},
            "<node_id>": {"kind": "device", "hostname", "agent_id": null,
                          "cve_lookup": {...}, "findings": [...]}}
}
```

Each CVE's text is stored once in `cves`; entries list one finding per CVE and
package. Keys are the graph's `node_id` values; endpoints and network devices
share the map and `kind` tells them apart (`counts.hosts` counts endpoints,
`counts.devices` devices). `findings` is `null` when the host was not scored,
came from an old `--scored` file, or a device lookup did not succeed.

`--scored PATH` reads `{"endpoints": [...], "cves": {...}, "warnings": [...]}`
(what `python -m vulnmapper.endpoints.score` writes) or the older plain list of
endpoints, which keeps its stored `risk_score` and has no full findings.

### Device CVEs

Switches, firewalls and access points have no Wazuh agent, so their CVEs come
from NVD, the US National Vulnerability Database. After assembly, every device
in the graph is looked up (after a live crawl and with `--network` alike).

**From identity to a product identifier.** When the crawler identifies a device
it also decides its software family from the system description, vendor and
sysObjectID (for Cisco, IOS XE, IOS XR, NX-OS and ASA are tested before plain
IOS, since an IOS XE description also says "IOS Software"). A rule table turns
family and firmware into a CPE, NVD's standard product name, e.g.
`cpe:2.3:o:cisco:ios:12.2\(55\)se12:*:*:*:*:*:*:*`:

| Family | CPE |
|---|---|
| Cisco IOS, IOS XE, NX-OS | `o:cisco:ios`, `o:cisco:ios_xe`, `o:cisco:nx-os` |
| Cisco ASA | `a:cisco:adaptive_security_appliance_software` |
| Fortinet FortiOS | `o:fortinet:fortios` |
| HP Comware | none: NVD has no Comware product, only some Comware 7 part numbers |
| Cisco IOS XR | none yet (recognised, so never taken for IOS) |

The CPE is first looked up in NVD's CPE dictionary: NVD answers a version it
has never listed with every CVE whose range happens to include it, so a CPE the
dictionary lacks is "unverified" and not asked. A listed CPE is asked for the
CVEs where that software is the vulnerable component (`isVulnerable`).

A family without a CPE uses a keyword search, under a strict rule because a
wrong match puts a false critical on the map: a CVE counts only when its
configuration data or its text names the same vendor and the device's product
line as a whole word ("1920" never matches "1920S"), and, where its versions can
be compared with the device's, the version falls inside them.

**Potential findings.** A device finding means the software version matches.
It does not prove the affected feature is enabled on that device. Findings
count fully in the score; `cve_lookup` marks them as potential.

**On each device node:** `cve_summary`, `top_cves`, `max_cvss` and `risk_score`,
built exactly as for hosts, and `cve_lookup` (`status`, `match`, `product`,
`cpe`, `source`, `fetched_at`, `stale`, `total`).

| Situation | `status` | `risk_score` |
|---|---|---|
| CPE query answered, CVEs found | `ok` | base score |
| CPE query answered, nothing found | `ok` | 0.0 |
| keyword search, CVEs found | `ok`, `match: keyword` | base score |
| keyword search, nothing found | `ok`, `match: keyword` | null |
| vendor, family or version missing | `unidentified` | null |
| NVD unreachable and nothing cached | `unavailable` | null |
| NVD could not confirm the query | `unverified` | null |
| device not polled | `unidentified` | null |

A 0.0 means "asked precisely, and NVD has nothing"; a failed, guessed or
skipped lookup never gives it. Problems go to `metadata.warnings`
(`nvd_unreachable`, `nvd_stale_cache`, `nvd_budget_exceeded`,
`device_unidentified`, each with node ids); `metadata.device_cves` counts the
devices looked up, by status, served from the cache, and the NVD requests made.

**Cache.** NVD answers are kept in `nvd-cache.json` beside the vulnerabilities
file (`data/nvd-cache.json` in practice; `--nvd-cache PATH` to move it), keyed
by query, so devices on the same software share an entry. An answer with CVEs
is fresh for 7 days, an empty one for 1 day. When NVD cannot be reached an
expired entry is used and marked `stale`. A corrupt cache is rebuilt. With a
warm cache a scan makes no NVD request.

**Rate and time.** Without a key requests are 6 seconds apart (NVD allows 5 per
30 seconds); with `NVD_API_KEY` set in the environment, 0.8 seconds. A
rate-limit or server error is retried twice. The stage has a time budget per
scan (`--nvd-budget`, default 180 seconds); devices it does not reach wait for
the next scan, with a warning. NVD never fails a scan. `--no-device-cves`
skips the stage, and device nodes are then written as before.

**Refresh without a rescan.** NVD publishes new CVEs every day:

```
python -m vulnmapper.devicecves --graph ../data/graph.json
```

re-runs only this stage on an existing graph, rewrites the graph's device CVE
fields and updates the device entries of `vulnerabilities.json` beside it. It
needs no SNMP and no Wazuh. For a graph written before software families were
recorded, the family is inferred only when unambiguous (a classic IOS version
string, a FortiGate, the Comware version format).

### Configuration checks

Each polled device is checked against a short list of configuration rules,
from SNMP data it already offers: column walks and GETs with the crawl's own
credential, never a write, a login or a port scan (two optional, off-by-default
tests below add a little to that). The stage runs after the
device CVEs; `--no-checklist` skips it and its SNMP reads, and the document is
then written exactly as before.

**Only published severities.** Every check points at a rule published by a
recognised body, and its severity is the one that body gave (DISA CAT I, II,
III = high, medium, low; NVD's own CVSS for the CVE). A check that no body
rates has severity null and is shown as "Advisory". Cisco IOS devices get the
Cisco STIG rule, other devices the generic Security Requirements Guide (SRG)
rule it derives from. "Related" means the rule covers the subject but its
condition is not exactly what the check tests.

| Check | Applies to | Severity | References (Cisco IOS / others) |
|---|---|---|---|
| `mgmt-telnet-enabled` | every device | high | STIG V-220608 / SRG V-202118, CAT I; CWE-319 |
| `mgmt-http-enabled` | every device | high | STIG V-220586 / SRG V-202049, CAT I; CWE-319 |
| `snmp-no-auth` | every device | medium | STIG V-220604, V-220605 / SRG V-202111, CAT II; CWE-319 |
| `snmp-default-community` | every device | high | NVD CVE-1999-0517 (CVSS 2.0 7.5); CWE-1392 |
| `spare-ports-in-used-vlan` | switches | medium | STIG V-220641 / SRG V-206666, CAT II |
| `access-ports-default-vlan` | switches | medium | STIG V-220642 / SRG V-206667, CAT II |
| `bpdu-guard-missing` | Cisco switches | medium | STIG V-220630 / SRG V-206655, CAT II |
| `port-security-disabled` | Cisco switches | Advisory | related: STIG V-220623, CAT I (asks for 802.1X) |

STIG rules are from the Cisco IOS Switch NDM STIG V3R9 and L2S STIG V3R3, SRG
rules from the NDM SRG V5R5 and L2S SRG V3R4; each reference carries its
document, release, STIG and SRG ids, CCI, NIST control and a link
(`vulnmapper/checklist/catalogue.py`). Not covered yet: root and loop guard,
trunk and native VLAN settings, 802.1X, and software past its support date.

**Results.** Each check ends in one of `pass`, `fail`, `not_applicable` (not
for this kind of device, or no data source for its vendor), `unknown` (it
applies but the data could not be read) or `not_checked` (the
default-community probe was not enabled). Missing data is never a pass.

**Access ports.** One definition serves every port check: a physical Ethernet
port that is a switch port and not an uplink. On Cisco, the VLAN membership
table decides "switch port" (it lists access ports and leaves trunks out);
elsewhere, being a bridge port does.

**What each check reads.**

- Telnet and HTTP: the TCP connection and listener tables. A device that lists
  no TCP socket at all over SNMP (the lab's Cisco switches) gives `unknown`,
  unless the connection test below is on.
- SNMP without authentication: the version of the credential that worked.
- Spare ports in a VLAN in use: the rule's finding is "If any access switch
  ports are not in use and not in an inactive VLAN, this is a finding." A
  spare port is an access port with no link since the device started
  (`ifOperStatus` without link, `ifLastChange` within 5 minutes of boot). A
  port that lost its link later may be a computer that is switched off, so
  it is not counted, only reported (`down_recently_not_counted`). A VLAN is
  in use when an access port in it has a link, when a host anywhere in the
  graph was learned on it, or when it is VLAN 1; any other VLAN counts as an
  unused (parking) VLAN. Whether a spare port is shut down does not change
  the result; the evidence says how many are `enabled` and `shut_down`, and
  lists `{port, vlan}`. Without the VLAN of each port (on Cisco `vmVlan`,
  elsewhere the PVID) the result is `unknown`. Not read: the rule's second
  step (the parking VLAN kept off every trunk) and its 802.1X exemption.
- Default VLAN: on Cisco `vmVlan`, elsewhere the 802.1Q PVID of each bridge
  port. Ports with a device attached are listed first.
- BPDU guard: CISCO-STP-EXTENSIONS-MIB, per port and global, following the
  MIB's rule for ports left at "default".
- Port security: CISCO-PORT-SECURITY-MIB, global switch and per port.

**Requests per device.** 10 for every device (1 GET and 9 column walks; one
more walk when `ifName` is empty and `ifDescr` is read instead), 15 for a
Cisco device; each walk is one or more GETBULKs. A table the device does not
answer costs one request. Only when BPDU guard differs between ports does a
Cisco switch need one more walk per access VLAN, to map its bridge ports to
interfaces. On the lab's captures that is 11 walks and GETs for the HP switch
and 16 for each Cisco device, on top of the crawl's own.

**Default community names.** `--check-default-communities` (off by default)
also sends each device two read-only SNMPv2c GETs of `sysName`, one with
`public` and one with `private`, with a 1 second timeout and no retry; the
network may log them as failed logins. Off, the check is `not_checked` with
the reason "probe not enabled", except when the scan's own credential is one
of these names, which is reported without a probe.

**Connection test for telnet and HTTP.** `--check-management-ports` (off by
default) is for devices that do not list their TCP listeners over SNMP. Only
those get one TCP connection to port 23 and one to port 80 on their
management address, with a 1 second timeout, closed as soon as it is
accepted. No data is sent and no login is tried. Accepted: the check fails,
with evidence that the port answered a connection test. Refused: it passes.
No answer: `unknown`, "no answer from the scanner's position", since a
filtered port proves nothing. Off, the `unknown` reason says the test is not
enabled.

**On each polled device node:** `config_checks` (one `{id, title, result,
reason}` per check), `config_findings` (one per failed check: `id`, `title`,
`severity`, `why`, `remediation`, `references`, `cwe`, `evidence`; port lists
hold at most 20 names plus `total`) and `config_summary` (`checks`, `results`
by result, `findings` by `high`, `medium`, `low`, `advisory`). A device that
was not polled gets none of them. `risk_score` and the base score are not
touched. `metadata.checklist` counts the devices checked, the results and the
findings, and says whether the probe (`probe_enabled`) and the connection
test (`port_test_enabled`) were on and where the data came from (`source`:
`scan`). Warnings: `checklist_data_missing` and
`checklist_unreadable`, with node ids. `metadata.timing.checklist_s` is the
stage's duration.

**From captures.** `scripts/checklist_sample_graph.py` evaluates raw SNMP
captures (`snmpwalk -On` output) of devices already in a graph and writes the
results onto them, with `metadata.checklist.source` set to say so. It contacts
no device.

### Unmanaged hosts

A host is an endpoint-kind node. A host with a Wazuh agent is managed, whether
the agent is active or disconnected; the Wazuh server is managed too. A host
without one is unmanaged: the scan found it in a switch's forwarding table, in
an LLDP or CDP announcement, or in an access point's client list, but nothing
reports its software, so its vulnerabilities are not known. It is a blind
spot. Network devices are not hosts.

Every host has `unmanaged` (true or false). There is no severity and no
score: `risk_score` stays null on an unmanaged host. `metadata.coverage` gives
`hosts`, `managed`, `unmanaged` and `managed_share` (null with no hosts).

**Three passive clues.** None of them touches the host.

- `mac_type`: `global`, or `local` when the MAC's locally administered bit is
  set. A local address is randomised (phones and laptops do this on Wi-Fi for
  privacy) or virtual (a virtual machine; the lab's Wazuh server has one). It
  names no manufacturer.
- `mac_vendor`: for a global MAC, the organisation IEEE's public registry
  gives for its block (the longest match of the 36-, 28- and 24-bit blocks),
  else null. `vendor` is not touched: on an agent it holds the operating
  system's vendor. Both fields are on every host with a MAC, managed or not.
  The registry ships as `vulnmapper/oui.tsv.gz` (about 560 KB), built by
  `scripts/build_oui.py` from IEEE's MA-L, MA-M and MA-S files; its header
  names the source and the date. Nothing is downloaded during a scan.
- Name from DNS: a host with an address and no name is looked up with the
  system resolver. This asks the site's DNS server, not the host, so it is on
  by default; `--no-name-lookup` turns it off. `hostname` is filled only when
  it is empty, with `name_source: "dns"`. Lookups run 32 at a time; an answer
  later than 1 second is not waited for, and no new lookup starts after 5
  seconds. `metadata.name_lookup` gives `asked`, `named` and `budget_reached`.

**Optional SNMP question.** `--probe-unmanaged-snmp` (off by default) asks
each unmanaged host with an address for its SNMP system group, with the
credentials given for the scan and never the factory names: one attempt, a 1
second timeout, 32 hosts at a time, at most 256 per scan (a warning,
`snmp_question_cap_reached`, when there are more).

The risk: this sends the owner's SNMP credential to machines nobody has
vouched for. A hostile machine simply receives it. That is why it is off.

A host that answers is usually a printer, a camera, a storage box or a small
switch. It gets `snmp: true`, its system name as `hostname` when it has none
(`name_source: "snmp"`), `sys_descr`, and `vendor`, `model`, `firmware` and
`software_family` where the vendor code recognises it. With a software family
it goes through the device CVE stage like a device (`cve_summary`,
`top_cves`, `max_cvss`, `cve_lookup`, `risk_score`). A host that has LLDP or
CDP neighbours or a forwarding table of its own is crawled as a device from
its address, so it is placed and checked like any other device. Either way it
keeps `unmanaged: true`. A host that does not answer is unchanged.
`metadata.snmp_question` gives `asked`, `answered`, `forwarding`, `cap` and
`cap_reached`.

**Planned:** an optional nmap service scan of unmanaged hosts, off by default.

## Liveness

```
python -m vulnmapper.liveness --graph ../data/graph.json [--state liveness.json]
                              [--threshold 2] [--agent-max-age 30]
```

Re-checks the nodes already in the graph (never writes it) and prints a state
document on stdout: per node `state` (`active` / `inactive` / `unknown`),
`method`, `misses`, `last_seen`, `last_checked`, `proven_methods`.

- Endpoints with an `agent_id` are checked by Wazuh agent check-in
  (`method: "agent"`) when `WAZUH_PASS` is set: one Manager API request per
  pass lists every agent's status and `lastKeepAlive`. Active with a check-in
  no older than `--agent-max-age` seconds (default 30) is a reply (agent 000,
  the manager, always is); an older check-in is a miss; `disconnected`, `pending` or
  `never_connected` makes the node inactive at once. If the login or request
  fails or takes over 5 seconds, those nodes keep their state for the pass
  (`reason: "agent_unavailable"`, and `agent_error` in the document). Without
  `WAZUH_PASS` they are pinged like any other endpoint.
- Pollable devices are probed by SNMP when `SNMP_COMMUNITIES` (or the other
  `SNMP_*` variables) is set, everything else by `ping -c 1 -W 1`.
- A Wi-Fi client of an access point that answers SNMP is checked against the
  AP's client list once per pass (`method: "wifi"`) instead of ping. Missing
  from the list is treated like a down port (inactive at once, recorded in
  `port_down` with `"port": "wifi"`); a later Wazuh check-in or reappearing
  in the list makes it active again.
- A wired host with a MAC and a known switch port that no faster method has
  ever proven (one that blocks ping, or has no IP) is looked up in its
  switch's forwarding table (`method: "mac-table"`): found on that port is a
  reply, not found a miss. Specific entries are fetched, never whole tables,
  one batched lookup per switch per pass; a switch over 2 s is skipped for the
  pass. A switch keeps a MAC for minutes, so this confirms presence and is
  slow to show absence; a down port still wins.
- A node goes inactive after `--threshold` misses on a method it has answered
  before (`agent` counts as answered from the start), or at once when its
  switch port is reported down (`method: "port"`; `port_down.since` is when
  the port was first seen down). A ping or SNMP reply in the same pass still
  wins, but an agent check-in is a stored time: it counts only if
  `lastKeepAlive` is later than `since`, which also revives the node (it
  reconnected some other way). Otherwise the node gets its earlier state
  back, with misses reset, once that port is up again or a new scan places it
  on another port; an up port never makes a node active by itself.
- Port states of every polled device are remembered between passes (`ports`).
  The document sets `rescan_suggested` with short `rescan_reasons` when a port
  goes from down to up with nothing in the graph linked to it, when the
  Manager API lists an active agent that is not in the graph, or when an
  access point lists a Wi-Fi client that is not in the graph. The suggestion
  stands until a new scan replaces the graph (`graph_scan_time`).

Credentials come from the environment only and are never logged, written or
placed in argv. The plugin runs it on a timer and starts the suggested scans.

## Tests

From `backend/`:

```
python -m unittest discover -s tests
```

or plain `pytest` (7 or later).

The tests use fixtures only and need no network access or credentials.
