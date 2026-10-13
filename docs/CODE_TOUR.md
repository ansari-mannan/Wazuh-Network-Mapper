# Code tour

A one-page map of the code: which files hold each part, how data moves
through a scan, the order of the stages, and every class with its role.

## The parts and their files

All Python paths are under `backend/vulnmapper/`, plugin paths under `plugin/`.

| Part | What it does | Files |
|---|---|---|
| Discovery | Crawls the network over SNMP from a seed, following LLDP and CDP neighbour tables; reads each device's identity, forwarding table, ARP table and port states | `network/crawl.py` (the crawler), `network/seeds.py`, `network/identity.py`, `network/vendors/`, `network/entity.py`, `network/roles.py`, `network/parse/` (table parsers), `network/snmp.py` (the only pysnmp user), `network/model.py`, `network/config.py`, `network/document.py` |
| Wazuh endpoints | Lists the agents and their inventory from the Manager API, and each agent's CVEs from the Indexer | `endpoints/wazuh.py`, `endpoints/inventory.py`, `endpoints/findings.py`, `scoring.py` |
| Assembler | Joins both sides into one graph and hangs each host off the switch port it sits on | `assemble/graph.py`, `assemble/mactable.py`, `assemble/nodes.py`, `hosts.py` (managed/unmanaged labels), `schema.py` |
| CVE lookup | Finds CVEs for network devices in NVD by software version, then the CVSS vector fields of every CVE found | `devicecves/stage.py`, `devicecves/families.py`, `devicecves/lookup.py`, `devicecves/nvd.py`, `devicecves/cache.py`, `devicecves/vectors.py`, `vulnfile.py` |
| Checklist | Checks each switch's configuration against DISA STIG / SRG rules | `checklist/collect.py`, `checklist/tables.py` (read during the crawl), `checklist/catalogue.py`, `checklist/evaluate.py`, `checklist/stage.py` |
| Service scan | Optional: nmap service detection on hosts without an agent, then the same NVD lookup | `servicescan/nmap.py`, `servicescan/stage.py` |
| Attack paths | The most likely routes to each asset the owner marked important (NIST IR 7788) | `attackpaths.py` |
| Liveness | Between scans, re-checks whether the nodes on the map still answer | `liveness/monitor.py`, `liveness/records.py`, `liveness/prober.py`, `liveness/cli.py` |
| Pipeline | Runs a scan: the inputs, assembly, then each stage in turn | `pipeline.py`, `common.py`, `__main__.py` |
| Plugin server | The dashboard's HTTP API; starts scans, the timed liveness check and attack-path recomputes as Python processes | `server/routes/index.ts`, `server/scan.ts`, `server/liveness.ts`, `server/autoRescan.ts`, `server/targets.ts`, `server/recommendations.ts`, `server/config.ts` |
| Plugin pages | Overview, topology map, scan settings, attack paths, vulnerability report, recommendations | `public/components/<page>/`, shared data hooks and pure helpers in `public/lib/`, file types in `common/types.ts` |

## How data moves through a scan

1. The plugin server starts `python -m vulnmapper` with the options the user
   picked; credentials come from the environment.
2. The scanner collects the Wazuh agents and scores each one from its CVEs.
3. It crawls the network from a seed. Each device it reaches is polled once:
   identity, neighbours, forwarding and ARP tables, port states and, for the
   checklist, its configuration tables.
4. The assembler joins the two into one graph. Each host is placed on a
   switch port by the best evidence available: an LLDP announcement, then
   the switches' forwarding tables, then its subnet. Hosts with no agent are
   added from the same tables and from access points' client lists.
5. The optional stages add to that graph in place: names, device CVEs from
   NVD, service scan results, CVE vector fields and configuration findings.
6. The scanner writes `graph.json`, `vulnerabilities.json` (every CVE
   finding) and `attack_paths.json` (routes to the protected assets). The
   server swaps them in only if the scan succeeded.
7. The pages read those files through the server's API. While liveness is
   on, the server re-checks the nodes on a timer and writes `liveness.json`;
   the map greys out what has gone, and a change can trigger a new scan.

## Stages, in pipeline order

These are the names `graph.json` lists in `metadata.stages`.

| # | Stage | Entry function | Default |
|---|---|---|---|
| 1 | Wazuh endpoints | `pipeline._read_endpoints` | on |
| 2 | Network crawl | `pipeline._read_network` | on |
| | (assembly) | `assemble.assemble` | always |
| 3 | SNMP question to unmanaged hosts | `hosts.run_snmp_question` | off |
| 4 | Reverse DNS names | `hosts.run_name_lookup` | on |
| 5 | Device CVEs (NVD) | `devicecves.stage.run_device_cves` | on |
| 6 | nmap service scan | `servicescan.stage.run_service_scan` | off |
| 7 | CVE vectors (NVD) | `devicecves.vectors.run_cve_vectors` | on |
| 8 | Configuration checks | `checklist.stage.run_checklist` | on |
| 9 | Attack paths | `attackpaths.run_attack_paths` | on |

Every optional stage (3 to 9) has the same shape:
`run_<stage>(scan: ScanContext) -> StageResult`. `Pipeline.run` calls them in
this order through `_run_stage`, which times each one, stores its block in
`metadata` and records its line in `metadata.stages`.

## Classes

### Data model

| Class | Role |
|---|---|
| `schema.Node` | One graph node, endpoint or device, as written to graph.json |
| `schema.Edge` | One graph edge: a device link or a host's link to its switch port |
| `network.model.Device` | A device as the crawler records it |
| `network.model.Link` | One device's report of a neighbour on a port |
| `network.model.Credential` | One SNMP credential to try |
| `network.parse.lldp.Neighbor` | One row of an LLDP or CDP neighbour table |
| `assemble.mactable.SwitchFdb` | One switch's forwarding table, indexed by MAC |
| `assemble.mactable.HostFact` | Where one MAC sits: switch, port, VLAN, IP |
| `assemble.mactable.MacTable` | The lookup host placement reads, built from every switch |
| `devicecves.lookup.Lookup` | The result of one NVD lookup: status, rows, product, CPE |
| `common.StageResult` | What one optional stage produced: its block, warnings, entries, rows and note |
| `pipeline.ScanContext` | One scan as the stages see it: options, graph, CVE catalogue, shared NVD client |
| `network.config.Config` | A crawl's limits and credentials |
| `schema.WazuhConfig`, `schema.IndexerConfig` | Connection settings read from the environment |

### Services

| Class | Role |
|---|---|
| `pipeline.Pipeline` | Runs a whole scan |
| `endpoints.wazuh.WazuhSource` | Talks to the Wazuh Manager API and Indexer |
| `network.crawl.Crawler` | The crawl's shared state and worker pool |
| `network.snmp.SnmpClient` | Every SNMP request, over one shared engine |
| `assemble.graph.GraphAssembler` | Joins endpoints and the network into the graph |
| `devicecves.nvd.NvdClient` | Rate-limited, time-boxed NVD queries |
| `devicecves.nvd.SystemClock` | The real clock, replaced by a fake in tests |
| `devicecves.cache.Cache` | NVD answers kept between scans |
| `checklist.evaluate.DeviceChecker` | The configuration checks for one device |
| `servicescan.nmap.NmapRunner` | Runs nmap |
| `attackpaths.AttackPathEngine` | Placement, reachability, starts and routes for one graph |
| `liveness.monitor.LivenessMonitor` | One liveness pass after another, carrying state between them |
| `liveness.prober.SystemProber` | How a liveness pass reaches the network: ping, SNMP, Wazuh |
| `VulnmapperPlugin` (`plugin/public/plugin.ts`, `plugin/server/plugin.ts`) | The plugin's browser and server halves, registered with the dashboard |

### Errors

All share the base `common.VulnmapperError`.

| Class | Raised when |
|---|---|
| `devicecves.nvd.NvdUnavailable` | NVD gives no useful answer (network error, repeated rate limit, 5xx) |
| `devicecves.nvd.NvdInvalidQuery` | NVD rejects a query as malformed |
| `devicecves.nvd.NvdBudgetExceeded` | The scan's NVD time budget has run out |
| `devicecves.lookup.Unanswered` | A CVE id lookup got no answer |
| `servicescan.nmap.NmapBudgetExceeded` | nmap did not finish inside its time budget |

## Tests

`backend/tests/` holds the unit tests and `test_golden.py`, which runs two
offline scans and three liveness passes and compares the files they write with
`tests/golden/`. `plugin/public/**/*.test.ts` are the plugin's tests;
`pages.render.test.tsx` compares the larger pages' HTML with stored snapshots.
