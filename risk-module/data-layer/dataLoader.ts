import mockAssets from "./mockAssets.json";
import mockVulnerabilities from "./mockVulnerabilities.json";
import topologyDefinition from "./topologyDefinition.json";

export type Asset = {
  id: string;
  hostname: string;
  os: string;
  exposure: string;
  criticality: string;
  segment: string;
};

export type Vulnerability = {
  id: string;
  assetId: string;
  cveId: string;
  cvss: number;
  title: string;
};

export type TopologyDefinition = {
  nodes: { id: string; label: string }[];
  edges: { source: string; target: string }[];
};

export function getAssets(): Asset[] {
  return mockAssets as Asset[];
}

export function getVulnerabilities(): Vulnerability[] {
  return mockVulnerabilities as Vulnerability[];
}

export function getTopology(): TopologyDefinition {
  return topologyDefinition as TopologyDefinition;
}
