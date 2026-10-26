// Graph types, modelled on the real graph.json shape.

// --- OVSS (backend/vulnmapper/scoring): a score per finding (one CVE on one
// node) and its tier, rolled up per node. Absent in graphs written before it.
export type Tier = 'P0' | 'P1' | 'P2' | 'P3';

// The OVSS fields of one finding: on vulnerabilities.json findings and on the
// graph's top_cves rows. score is null (tier "Unrated") when no CVSS score exists.
export type OvssFinding = {
  score?: number | null;
  tier?: Tier | 'Unrated';
  cvss_tool?: number | null;  // what the scanner reported (Wazuh indexer / NVD)
  cvss_used?: number | null;  // the CVSS score OVSS used
  cvss_src?: 'CNA' | 'ADP' | 'tool' | null;
  cvss_ver?: string | null;
  kev?: boolean;              // in CISA's Known Exploited Vulnerabilities
  epss?: number;              // FIRST EPSS probability, 0 when not listed
  exposure?: number;
  dependency?: number;
  confidence?: 'confirmed' | 'potential';
  conflict?: 0 | 1;           // CNA/ADP and tool scores (same version) differ by 1.0+
};

export type OvssStatus = 'assessed' | 'Unrated' | 'Unassessed';

// A node's OVSS roll-up. risk_score (on every node) is its OVSS: the highest of
// its findings', null unless assessed. Unassessed is not clean: nothing was found
// or looked up, and ovss_reason says which.
export type OvssNode = {
  node_tier?: Tier | null;
  ovss_hist?: Record<Tier | 'Unrated', number>;
  ovss_status?: OvssStatus;
  ovss_reason?: string | null;
  exposure?: number;
  exposure_flag?: 'exposure_unknown' | null;
  dependency?: number;
  importance?: number;        // the FIPS 199 weight from targets.json, 0 when unmarked
  kev_count?: number;
};

// metadata.threat_feeds: whether KEV and EPSS were fresh, stale or unavailable.
export type FeedState = 'fresh' | 'stale' | 'unavailable';
export type ThreatFeeds = { kev: FeedState; epss: FeedState; kev_date: string | null; epss_date: string | null };

export type CVE = OvssFinding & {
  cve: string;
  severity: string;
  cvss: number | null;
  cvss_version: string | null;
  package: string | null;
  version: string | null;
  description: string | null;
  // Optional: absent from older graph files and from some CVE documents.
  reference?: string | null;
  published_at?: string | null;
  detected_at?: string | null;
};

// Distinct-CVE counts for an endpoint, by CVSS v3 band (unknown = no score).
export type CveSummary = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  max_cvss: number | null;
};

// Common fields shared by both kinds of node.
type GraphNodeBase = OvssNode & {
  node_id: string;
  kind: "device" | "endpoint";
  ip: string | null;
  hostname: string | null;
  vendor: string | null;
  model: string | null;
  firmware: string | null;
  serial: string | null;
  mac: string | null;
  discovery_method: string;
  status: string;
  risk_score: number | null;
  discovery_order: number;
  parent_id: string | null;
  role: string;
  stale?: boolean;
  max_cvss?: number | null;
};

// How a network device's CVEs were looked up (backend/vulnmapper/devicecves).
//   ok           NVD answered; match "cpe" (exact software identifier) or
//                "keyword" (product name in NVD's descriptions)
//   unidentified vendor, software family or version missing, or never polled
//   unavailable  NVD could not be reached and nothing was cached
//   unverified   NVD could not confirm the query (version not in its dictionary)
// Absent in graphs written before devices were looked up.
export type CveLookupStatus = "ok" | "unidentified" | "unavailable" | "unverified";

export type CveLookup = {
  status: CveLookupStatus;
  match: "cpe" | "keyword" | null;
  product: string | null;   // "Cisco IOS 12.2(55)SE12"
  cpe: string | null;
  source: string;           // "nvd", or "nmap" from the service scan
  fetched_at: string | null;
  stale: boolean;           // an expired cached answer, NVD unreachable
  total: number | null;     // distinct CVEs, when status is ok
  potential?: boolean;      // service-scan match: a version match, not proof
};

// An open port the service scan found; service fields null where undetected.
export type OpenPort = {
  port: number;
  protocol: string;
  service: string | null;
  product: string | null;
  version: string | null;
};

// Device configuration checks (backend/vulnmapper/checklist), one result per
// check:
//   pass            the data was read and the device complies
//   fail            the data was read and the device does not comply
//   not_applicable  not for this kind of device, or no data source for its vendor
//   unknown         the check applies but the data could not be read
//   not_checked     the owner did not enable it (the default-community probe)
// Absent on devices that were not polled and in graphs written before the checks.
export type ConfigResult = 'pass' | 'fail' | 'not_applicable' | 'unknown' | 'not_checked';

export type ConfigCheck = {
  id: string;
  title: string;
  result: ConfigResult;
  reason?: string; // for not_applicable, unknown and not_checked
  unused_vlans?: number[]; // spare-ports-in-used-vlan on a pass: VLANs taken for unused
};

// A published rule a check points at. severity is the publisher's own
// (DISA CAT I/II/III = high/medium/low); relation "related" means the rule
// covers the subject but its condition is not exactly what the check tests.
export type ConfigReference = {
  source: string;            // "DISA", "NVD"
  document: string;          // "Cisco IOS Switch L2S STIG"
  release: string | null;
  rule_id: string;           // "V-220630", "CVE-1999-0517"
  stig_id: string | null;
  srg_id: string | null;
  title: string;
  url: string;
  severity: string | null;
  category: string | null;   // "CAT II"
  cvss?: { version: string; score: number; vector: string; source: string } | null;
  cci: string | null;
  nist: string | null;
  relation: 'requires' | 'related';
};

// What a failed check found. Port lists hold at most 20 entries; total is the full count.
export type ConfigEvidence = {
  ports?: Array<string | { port: string; vlan: number }>; // spare ports: {port, vlan}
  total?: number;
  enabled?: number;                   // spare ports: administratively up ...
  shut_down?: number;                 // ... or shut down
  down_recently_not_counted?: number; // spare ports: lost the link after boot, not counted
  unused_vlans?: number[];            // spare ports: VLANs the check took for unused (parking)
  with_link?: number;       // default VLAN: ports with a device attached (listed first)
  port?: number;            // a TCP port the device listens on
  snmp_version?: string;
  communities?: string[];   // factory names that answered
  found_by?: string;        // who found it: the probe, or the connection test
};

export type ConfigFinding = {
  id: string;
  title: string;
  severity: 'high' | 'medium' | 'low' | null; // null: no published severity ("Advisory")
  why: string;
  remediation: string;
  references: ConfigReference[];
  cwe: string | null;
  evidence: ConfigEvidence | null;
};

export type ConfigSummary = {
  checks: number;
  results: Record<ConfigResult, number>;
  findings: { high: number; medium: number; low: number; advisory: number };
};

// metadata.checklist
export type ChecklistMeta = {
  devices_checked: number;
  results: Record<ConfigResult, number>;
  findings: { high: number; medium: number; low: number; advisory: number };
  probe_enabled: boolean;
  port_test_enabled?: boolean; // the telnet/HTTP connection test; absent in older graphs
  source: string; // "scan", or where the data came from ("captures 2026-10-08")
};

// One interface of a device. state: up; link_lost (down, but a neighbour is
// listed on it or it was up in the previous scan); unused; shutdown (admin down).
export type PortState = 'up' | 'link_lost' | 'unused' | 'shutdown';
export type DevicePort = {
  name: string;
  oper?: string;
  admin?: string | null;
  type?: number | null;        // IANAifType number
  speed_mbps?: number | null;
  alias?: string | null;
  state: PortState;
};

export type DeviceNode = GraphNodeBase & {
  kind: "device";
  // Device CVEs (potential: matched by software version). Absent in older graphs.
  top_cves?: CVE[];
  cve_summary?: CveSummary | null;
  cve_lookup?: CveLookup;
  software_family?: string;
  chassis_id?: string;
  pollable?: boolean;
  uplink_ports?: string[];
  neighbor_ports?: string[];
  // of the ports above, those known only from the neighbour's side of the link
  // (the device lists no LLDP neighbours over SNMP, e.g. a FortiGate)
  inferred_ports?: string[];
  port_status?: Record<string, string>;
  port_status_note?: string;
  // Every interface by ifIndex (backend assemble/ports.py); absent in older graphs.
  ports?: DevicePort[];
  // An access point: how many Wi-Fi clients it reported.
  wifi_clients?: number;
  // A host without an agent that answered SNMP and turned out to forward
  // traffic, crawled as a device: it still has no agent.
  unmanaged?: boolean;
  snmp?: boolean;
  sys_descr?: string | null;
  // Configuration checks; absent when the device was not polled or not checked.
  config_checks?: ConfigCheck[];
  config_findings?: ConfigFinding[];
  config_summary?: ConfigSummary;
};

export type OsvMatch = {
  status: 'ok' | 'unavailable' | 'skipped';
  reason: string | null; // why it is not ok, e.g. "OSV unavailable"
  ecosystem?: string; // "Ubuntu:22.04:LTS"
  packages?: number;
};

export type EndpointNode = GraphNodeBase & {
  kind: "endpoint";
  agent_id: string | null;
  // The worst distinct CVEs (up to 10); the full list is in vulnerabilities.json.
  top_cves: CVE[];
  // null when the endpoint could not be scored; absent in older graph files.
  cve_summary?: CveSummary | null;
  // Present (true) only on the Wazuh server's own node (agent 000).
  is_wazuh_server?: boolean;
  // Why it is unscored, when known: "no_inventory" (the Wazuh indexer holds no
  // package inventory for it, so its CVEs are unknown, not zero).
  unscored_reason?: string;
  // The Wazuh server only: its own package list matched with OSV.dev, which
  // Wazuh does not index for the manager (backend/vulnmapper/endpoints/osv.py).
  osv?: OsvMatch;
  // A Wi-Fi client: the SSID, the access point (node_id) and the radio.
  wifi?: WifiInfo;
  // The VLAN its switch learned it on.
  vlan?: number;
  // Hosts (backend/vulnmapper/hosts.py); absent in older graphs.
  unmanaged?: boolean;                // true: no Wazuh agent reports from it
  mac_type?: 'global' | 'local';      // local: randomised or virtual, no manufacturer
  mac_vendor?: string | null;         // IEEE registry organisation for a global MAC
  name_source?: 'dns' | 'snmp' | 'netbios'; // where hostname came from when not from Wazuh
  // It answered the optional SNMP question: what it reported, and, with a
  // known software family, the same CVE lookup as a device.
  snmp?: boolean;
  sys_descr?: string | null;
  software_family?: string;
  cve_lookup?: CveLookup;
  // The optional service scan (backend/vulnmapper/servicescan): open ports it
  // found and a guessed device type. Absent unless the host was scanned.
  open_ports?: OpenPort[];
  device_hint?: string;
};

// metadata.coverage: how many hosts a Wazuh agent reports from.
export type Coverage = {
  hosts: number;
  managed: number;
  unmanaged: number;
  managed_share: number | null;
};

export type WifiInfo = { ssid: string | null; access_point: string; radio: string | null };

export type GraphNode = DeviceNode | EndpointNode;

export type GraphEdge = {
  source: string;
  target: string;
  type: "lldp" | "endpoint_link";
  local_port?: string;
  remote_port?: string;
  source_name?: string;
  target_name?: string;
  confidence?: string;
  inferred?: boolean;
  // A device link found only over CDP: "cdp" (absent for LLDP).
  protocol?: string;
};

export type GraphWarning = {
  type: string;
  ip?: string;
  nodes?: { node_id: string; hostname: string | null; status: string; stale: boolean }[];
  [key: string]: unknown;
};

// metadata.stages: one entry per scanner stage, in run order. Absent in older graphs.
export type ScanStageOutcome = {
  name: string;
  status: 'ran' | 'skipped' | 'failed'; // failed: the stage crashed and the scan went on without it
  seconds: number | null;
  note: string | null; // e.g. "nmap not installed", "9 devices looked up, 2 NVD requests"
};

export type Metadata = {
  scan_time?: string;
  stages?: ScanStageOutcome[];
  network_scan_time?: string;
  seed?: string | null;
  warnings?: GraphWarning[];
  attack_path_sources?: string[];
  checklist?: ChecklistMeta;
  coverage?: Coverage;
  threat_feeds?: ThreatFeeds;
  // the optional SNMP question to unmanaged hosts, when it ran
  snmp_question?: { asked: number; answered: number; forwarding: number; cap: number; cap_reached: boolean };
  name_lookup?: { asked: number; named: number; budget_reached: boolean };
  // a live crawl: the device node ids that answered the community typed in the
  // scan form, and those that answered the server's SNMP settings (labels only)
  snmp?: { entered: string[]; server: string[] };
  // the device-CVE stage, when it ran; api_key says only whether a key was used
  device_cves?: { api_key?: boolean; [key: string]: unknown };
  counts?: {
    nodes: number;
    endpoints: number;
    devices: number;
    fdb_discovered_hosts: number;
    lldp_edges: number;
    endpoint_edges: number;
    unparented_endpoints: number;
  };
  [key: string]: unknown;
};

export type GraphResponse = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  metadata: Metadata;
};

// The shared recommendations tracker (recommendations.json beside the graph).
// `open` is the implicit default and is never stored, so the file holds only
// the items a user has moved off Open.
// GET /api/vulnmapper/files: each served file's modified time (ISO), null when absent.
export type FileTimes = { graph: string | null; vulnerabilities: string | null; attackPaths: string | null };

export type RecommendationStatus = 'open' | 'in_progress' | 'done' | 'accepted_risk';

// affected and findings: what the item covered when its status was set (absent
// in older files), so a later scan that finds more can reopen it.
export type RecommendationsFile = {
  statuses: Record<
    string,
    { status: RecommendationStatus; updated: string; affected?: string[]; findings?: number }
  >;
};

// Scan state reported by GET /api/vulnmapper/scan/status. After a successful
// scan the status returns to idle with a completion message.
export type ScanStatus = 'idle' | 'running' | 'failed';

// What started a scan: the scan form, the schedule, or the liveness check's
// automatic rescan.
export type ScanTrigger = 'manual' | 'scheduled' | 'automatic';

export type ScanState = {
  status: ScanStatus;
  trigger?: ScanTrigger;
  message: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  // The server's defaults for the scan form's active checks.
  defaults?: ActiveChecks;
  // While running: the stage the scanner last announced, e.g. "Looking up device CVEs in NVD".
  stage?: string | null;
  // Whether nmap is on the dashboard server's PATH (the nmap switch needs it).
  nmapAvailable?: boolean;
  // vulnmapper.seeds: where the network crawl starts (empty: the server's default gateway).
  seeds?: string[];
  // After a completed scan: whether its NVD lookups used an API key (null: no
  // device-CVE stage). Only the scanner's boolean; the key itself is never read.
  nvdKey?: boolean | null;
  // After a completed scan: its graph's metadata.warnings and metadata.snmp
  // (device ids by the credential they answered; labels only).
  warnings?: GraphWarning[];
  snmp?: Metadata['snmp'];
  // After a completed scan: CVE records are still arriving, and the scores are
  // rescored with them once they have (the files then change on disk).
  refining?: boolean;
};

// Scheduled scans (schedule.json beside the graph; GET/POST /api/vulnmapper/schedule).
// Every N minutes or hours runs on the server's local minutes or hours
// divisible by N; daily at dailyHour:00.
export type ScheduleFrequency = 'off' | '15m' | '30m' | '1h' | '3h' | '6h' | '12h' | 'daily';

export type ScheduledRun = {
  at: string; // ISO time the slot fired
  status: 'completed' | 'failed' | 'skipped';
  message: string;
};

export type ScheduleFile = {
  frequency: ScheduleFrequency;
  dailyHour: number; // 0-23, server local time
  lastRun: ScheduledRun | null;
};

export type ScheduleResponse = ScheduleFile & {
  nextRun: string | null; // ISO
  timeZone: string; // the server's IANA time zone, for display
};

// Scan history (history/index.json beside the graph, newest first, last 10;
// GET /api/vulnmapper/history and /api/vulnmapper/history/:id/changes).
export type HistoryEntry = {
  id: string; // the finish time, folder-safe: 2026-10-13T10-30-00-000Z
  time: string; // ISO
  trigger: ScanTrigger;
  files: string[]; // which of graph.json, vulnerabilities.json, attack_paths.json were archived
  counts: {
    devices: number;
    endpoints: number;
    cvesConfirmed: number; // distinct CVEs per asset, summed
    cvesPotential: number;
    configFindings: number;
  };
  stages: ScanStageOutcome[]; // the scan's metadata.stages
};

export type ArchivedScan = {
  entry: HistoryEntry;
  graph: GraphResponse;
  vulns: VulnerabilitiesDoc | null;
  attackPaths: AttackPathsDoc | null;
};

// GET /api/vulnmapper/history/:id/changes: the scan and the one before it.
export type HistoryChangesResponse = { current: ArchivedScan; previous: ArchivedScan | null };

// The scan's optional active checks, each off unless the owner turns it on
// (config vulnmapper.<key>; the scan form's choice wins per scan).
export type ActiveChecks = {
  checkDefaultCommunities: boolean; // --check-default-communities
  checkManagementPorts: boolean;    // --check-management-ports
  probeUnmanagedSnmp: boolean;      // --probe-unmanaged-snmp
  nmapUnmanaged: boolean;           // --nmap-unmanaged
};

// Liveness (GET /api/vulnmapper/liveness): per node_id, whether the node still
// answers. method is how it was last checked: "agent" (Wazuh agent check-in),
// "icmp", "snmp", "port" (its switch port went down) or null (no probe possible).
export type LivenessState = 'active' | 'inactive' | 'unknown';

export type NodeLiveness = {
  state: LivenessState;
  method: string | null;
  last_seen?: string | null;
  last_checked?: string;
  misses?: number;
  proven_methods?: string[];
  reason?: string; // e.g. "shared_ip", "agent_unavailable", "agent_not_listed"
  // the agent's last known status and check-in time, from the Manager API
  agent?: { status: string | null; last_keepalive: string | null };
  // set while method is "port": the down port and the state to restore once
  // it is up again (or the node is placed elsewhere by a new scan)
  // since: when that port was first seen down; an agent check-in only counts
  // as a reply if it is later than this
  port_down?: {
    device: string;
    port: string;
    previous_state: LivenessState | null;
    since?: string;
  };
};

export type LivenessResponse = {
  enabled: boolean;
  intervalSeconds: number;
  checkedAt: string | null;
  nodes: Record<string, NodeLiveness>;
  /** the graph file's modified time (ISO), null if there is none */
  graphMtime: string | null;
};

// --- Attack paths (data/attack_paths.json, backend/vulnmapper/attackpaths.py) ---
// The exact shape of the committed file; no field is invented.

// FIPS 199 impact of losing a target.
export type Importance = 'high' | 'moderate' | 'low';

export type AttackStartKind = 'managed_host' | 'unmanaged_host' | 'spare_ports';

export type AttackSource = { title: string; url: string };

// A device finding shown as context on a step (it adds no step of its own).
// severity null = no published severity ("Advisory").
export type AttackFinding = { id: string; title: string; severity: 'high' | 'medium' | 'low' | null };

// One step along a route. A takeover step (weakness or misconfiguration) reaches
// `to`; a transit step only crosses a router into the target's VLAN.
export type AttackStep = {
  kind: 'weakness' | 'misconfiguration' | 'transit';
  from: string;
  to: string;
  value: number;
  source?: AttackSource;
  // weakness
  cve?: string;
  attack_vector?: string;
  attack_complexity?: string;
  // misconfiguration
  check?: string;
  title?: string;
  access_complexity?: string;
  // transit
  through?: string;
  note?: string;
  // takeover steps carry the reached asset's OVSS and its other findings
  destination_ovss?: number | null;
  context_findings?: AttackFinding[];
};

export type AttackRoute = {
  target: string;
  start: string;
  start_kind: AttackStartKind;
  steps: AttackStep[];
  likelihood: number;
  highest_ovss: number; // the highest node OVSS along the route
  crosses_router: boolean;
  narrative: string;
  rank: number;
  importance: Importance;
};

export type AttackTarget = {
  id: string;
  importance: Importance;
  note: string | null;
  present: boolean;
  label?: string;
  routes?: AttackRoute[];
  reason?: string; // present false: why the id is missing from the graph
};

export type AttackStartingPoint = {
  id: string;
  kind: AttackStartKind;
  vlans: number[];
  switch?: string; // spare ports: the node id of the switch that holds them
  switch_label?: string; // ...and its name
  ports?: string[]; // spare ports: their ifNames in this VLAN (the checklist caps the list)
  listed_ports?: number;
  spare_ports_on_switch?: number;
  list_truncated?: boolean;
};

export type AttackAsset = {
  id: string;
  kind: string;
  label: string;
  dependants: number;
  verified: boolean;
  routes_through: number;
};

export type AttackPathsMetadata = {
  // 'ok' | 'no_targets' from the engine; 'absent' is the route's synthetic
  // state when the file has not been computed yet. The rest are present only
  // for a real file.
  state: 'ok' | 'no_targets' | 'absent';
  computed_at?: string;
  source_scan?: string | null;
  keep_per_target?: number;
  counts?: Record<string, number>;
  sources?: AttackSource[];
  reachability?: string[];
  limits?: string[];
  most_shared_asset?: string | null;
};

export type AttackPathsDoc = {
  metadata: AttackPathsMetadata;
  targets: AttackTarget[];
  starting_points: AttackStartingPoint[];
  per_asset: AttackAsset[];
  not_placed: Array<{ id: string; reason: string }>;
  // hosts not used as starts because their Wazuh agent is offline or (when
  // the recompute had a liveness pass for this graph) liveness marks them
  // inactive; absent in older files
  offline_starts?: Array<{ id: string; kind: AttackStartKind; reason: 'offline'; detail: string }>;
};

// --- Vulnerabilities (data/vulnerabilities.json, backend/vulnmapper/vulnfile.py) ---
// The full per-asset CVE list. The graph carries only each node's worst CVEs;
// the complete list is here. A CVE's text is stored once in `cves` and each
// host lists slim findings that point at it by id. The exact file shape.

// One CVE in the shared catalogue (keyed by CVE id). Same fields as a graph CVE
// without the per-host package/version/detected_at.
export type CatalogueCve = {
  cvss: number | null;
  cvss_version: string | null;
  severity: string;
  description: string | null;
  reference?: string | null;
  published_at?: string | null;
};

// One finding on a host: the CVE id, the affected package and its version,
// and its OVSS fields.
export type VulnFinding = OvssFinding & {
  cve: string;
  package: string | null;
  version: string | null;
  detected_at: string | null;
  source?: 'osv'; // the Wazuh server's own packages matched with OSV.dev: potential
};

// A host's entry. `kind` endpoint = a Wazuh agent (findings confirmed); kind
// device, or an endpoint carrying a cve_lookup (an unmanaged host looked up by
// version), means the findings are potential. findings is null when the full
// list is not available.
export type VulnHostEntry = {
  kind: 'endpoint' | 'device';
  hostname: string | null;
  agent_id: string | null;
  findings: VulnFinding[] | null;
  cve_lookup?: CveLookup;
};

export type VulnerabilitiesDoc = {
  // 'absent' is the route's synthetic state when the file has not been produced
  // yet; a real file has scan_time and counts instead.
  metadata: { scan_time?: string; counts?: Record<string, number>; state?: 'absent' };
  cves: Record<string, CatalogueCve>;
  hosts: Record<string, VulnHostEntry>;
  // The report's organisation/owner name, injected by the server from config
  // (vulnmapper.reportOrg); not part of the file on disk.
  org?: string;
};
