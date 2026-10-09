// Graph types, modelled on the real graph.json shape. Ported from
// frontend/lib/vulnmapperApi.ts.

export type CVE = {
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
type GraphNodeBase = {
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
  source: string;           // "nvd"
  fetched_at: string | null;
  stale: boolean;           // an expired cached answer, NVD unreachable
  total: number | null;     // distinct CVEs, when status is ok
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
  port_status?: Record<string, string>;
  port_status_note?: string;
  // An access point: how many Wi-Fi clients it reported.
  wifi_clients?: number;
  // Configuration checks; absent when the device was not polled or not checked.
  config_checks?: ConfigCheck[];
  config_findings?: ConfigFinding[];
  config_summary?: ConfigSummary;
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
  // A Wi-Fi client: the SSID, the access point (node_id) and the radio.
  wifi?: WifiInfo;
  // The VLAN its switch learned it on.
  vlan?: number;
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

export type Metadata = {
  scan_time?: string;
  network_scan_time?: string;
  seed?: string | null;
  warnings?: GraphWarning[];
  attack_path_sources?: string[];
  checklist?: ChecklistMeta;
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

// Scan state reported by GET /api/vulnmapper/scan/status. After a successful
// scan the status returns to idle with a completion message.
export type ScanStatus = 'idle' | 'running' | 'failed';

export type ScanState = {
  status: ScanStatus;
  message: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  // The server's defaults for the scan form (vulnmapper.checkDefaultCommunities).
  defaults?: { checkDefaultCommunities: boolean };
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
