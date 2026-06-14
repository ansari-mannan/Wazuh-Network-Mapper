/**
 * Thin /api/* client + graph types. Ported from the POC's
 * gui/frontend/src/api.js. Everything is same-origin now (one Next app), so
 * there is no CORS concern. Calls throw on non-2xx (except 202) with the
 * server's `error` message, matching the POC's `asJson` helper.
 */

// ---- Graph types (modelled on the real graph.json shape) ------------------

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
};

export type Metadata = {
  scan_time?: string;
  network_scan_time?: string;
  seed?: string | null;
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

export type ScanStatusResponse = {
  status: string;
  error: string | null;
  startedAt: string | null;
  finishedAt: string | null;
};

// ---- HTTP helper ----------------------------------------------------------

async function asJson<T>(res: Response): Promise<T> {
  const body = await res.json().catch(() => ({}));
  if (!res.ok && res.status !== 202) {
    throw new Error(body.error || `${res.status} ${res.statusText}`);
  }
  return body as T;
}

// ---- API calls ------------------------------------------------------------

export function getConfig(): Promise<{ community: string }> {
  return fetch("/api/config").then((r) => asJson(r));
}

export function getGraph(): Promise<GraphResponse> {
  return fetch("/api/graph").then((r) => asJson(r));
}

export function startScan(community: string): Promise<{ status: string; error?: string }> {
  return fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ community }),
  }).then((r) => asJson(r));
}

export function getScanStatus(): Promise<ScanStatusResponse> {
  return fetch("/api/scan/status").then((r) => asJson(r));
}
