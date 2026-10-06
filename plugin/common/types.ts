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

export type DeviceNode = GraphNodeBase & {
  kind: "device";
  chassis_id?: string;
  pollable?: boolean;
  uplink_ports?: string[];
  neighbor_ports?: string[];
  port_status?: Record<string, string>;
  port_status_note?: string;
};

export type EndpointNode = GraphNodeBase & {
  kind: "endpoint";
  agent_id: string | null;
  top_cves: CVE[];
};

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
};

export type LivenessState = 'active' | 'inactive' | 'unknown';

export type NodeLiveness = {
  state: LivenessState;
  method: string | null;
  last_seen?: string;
  last_checked?: string;
  misses?: number;
  proven_methods?: string[];
};

export type LivenessResponse = {
  enabled: boolean;
  intervalSeconds: number;
  checkedAt: string | null;
  nodes: Record<string, NodeLiveness>;
};
