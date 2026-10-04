/**
 * Abstraction layer: aggregates data layer + risk engine + topology engine.
 * UI only talks to this service.
 */

import { getAssets, getVulnerabilities, getTopology } from "../data-layer/dataLoader";
import type { Asset, Vulnerability, TopologyDefinition } from "../data-layer/dataLoader";
import { getExposureMultiplier } from "../risk-engine/exposureMultiplier";
import { getCriticalityWeight } from "../risk-engine/assetCriticality";
import { aggregateTopVulnerabilities } from "../risk-engine/aggregation";

export type AssetWithRisk = Asset & {
  aggregatedRisk: number;
  topVulnerabilities: Vulnerability[];
};

export type DashboardSummary = {
  overallRisk: number;
  highRiskAssetCount: number;
  internetFacingCritical: number;
  lateralMovementRisk: number;
};

export type TopologyNode = { id: string; label: string };
export type TopologyEdge = { source: string; target: string };

export function getDashboardSummary(): DashboardSummary {
  const assets = getAssets();
  const vulns = getVulnerabilities();
  const topology = getTopology();

  const assetRisks = assets.map((a) => {
    const assetVulns = vulns.filter((v) => v.assetId === a.id);
    const scores = assetVulns.map((v) => v.cvss);
    const exp = getExposureMultiplier(a.exposure);
    const crit = getCriticalityWeight(a.criticality);
    const avg = aggregateTopVulnerabilities(scores, 3) || 0;
    return avg * exp * crit;
  });

  const overallRisk =
    assetRisks.length > 0
      ? assetRisks.reduce((a, b) => a + b, 0) / assetRisks.length
      : 0;
  const highRiskAssetCount = assetRisks.filter((r) => r >= 7.5).length;
  const internetFacingCritical = assets.filter(
    (a) => a.exposure === "internet-facing" && (a.criticality === "high" || a.criticality === "critical")
  ).length;
  const lateralMovementRisk = 6.2; // static for MVP

  return {
    overallRisk: Math.round(overallRisk * 10) / 10,
    highRiskAssetCount,
    internetFacingCritical,
    lateralMovementRisk,
  };
}

export function getAssetsWithRisk(): AssetWithRisk[] {
  const assets = getAssets();
  const vulns = getVulnerabilities();

  return assets.map((asset) => {
    const assetVulns = vulns
      .filter((v) => v.assetId === asset.id)
      .sort((a, b) => b.cvss - a.cvss);
    const topVulns = assetVulns.slice(0, 3);
    const scores = assetVulns.map((v) => v.cvss);
    const exp = getExposureMultiplier(asset.exposure);
    const crit = getCriticalityWeight(asset.criticality);
    const avg = aggregateTopVulnerabilities(scores, 3) || 0;
    const aggregatedRisk = Math.round(avg * exp * crit * 10) / 10;

    return {
      ...asset,
      aggregatedRisk,
      topVulnerabilities: topVulns,
    };
  });
}

export function getAssetDetail(assetId: string): AssetWithRisk | null {
  const list = getAssetsWithRisk();
  return list.find((a) => a.id === assetId) ?? null;
}

export function getTopologyForUI(): { nodes: TopologyNode[]; edges: TopologyEdge[] } {
  const t = getTopology();
  return {
    nodes: t.nodes,
    edges: t.edges,
  };
}

export function getExecutiveReport(): {
  totalEnvironmentRisk: number;
  topHighRiskAssets: { hostname: string; risk: number }[];
} {
  const summary = getDashboardSummary();
  const assets = getAssetsWithRisk();
  const top5 = [...assets]
    .sort((a, b) => b.aggregatedRisk - a.aggregatedRisk)
    .slice(0, 5)
    .map((a) => ({ hostname: a.hostname, risk: a.aggregatedRisk }));

  return {
    totalEnvironmentRisk: summary.overallRisk,
    topHighRiskAssets: top5,
  };
}

export type Alert = {
  id: string;
  assetId: string;
  message: string;
  severity: "low" | "medium" | "high" | "critical";
  timestamp: string;
};

function getSeverityFromCvss(cvss: number): "low" | "medium" | "high" | "critical" {
  if (cvss >= 9.0) return "critical";
  if (cvss >= 7.0) return "high";
  if (cvss >= 4.0) return "medium";
  return "low";
}

export function getRecentAlerts(): Alert[] {
  const vulns = getVulnerabilities();

  const alerts = vulns
    .slice(0, 8)
    .map((v, i) => ({
      id: `alert-${v.id}`,
      assetId: v.assetId,
      message: `${v.title} (${v.cveId}) detected on ${v.assetId}`,
      severity: getSeverityFromCvss(v.cvss),
      timestamp: new Date(Date.now() - i * 1000 * 60 * 60).toISOString(),
    }));

  return alerts;
}

export function getVulnerabilityReport() {
  const assets = getAssets();
  const vulns = getVulnerabilities();
  const assetLookup = new Map<string, string>();
  assets.forEach((a) => assetLookup.set(a.id, a.hostname));

  const vulnerabilities = vulns.map((v) => ({
    ...v,
    assetHostname: assetLookup.get(v.assetId) ?? v.assetId,
    severity: getSeverityFromCvss(v.cvss),
  }));

  const perDevice = assets.map((a) => {
    const assetVulns = vulnerabilities.filter((v) => v.assetId === a.id);
    return {
      assetId: a.id,
      hostname: a.hostname,
      count: assetVulns.length,
      highestCvss: assetVulns.length > 0 ? Math.max(...assetVulns.map((v) => v.cvss)) : 0,
      highCount: assetVulns.filter((v) => v.severity === "high" || v.severity === "critical").length,
    };
  });

  return { vulnerabilities, perDevice };
}

export function getAttackPathAnalysis() {
  const topology = getTopology();
  const edgesMap = new Map<string, string[]>();
  for (const edge of topology.edges) {
    const src = edge.source;
    if (!edgesMap.has(src)) edgesMap.set(src, []);
    edgesMap.get(src)?.push(edge.target);
  }

  const assets = getAssetsWithRisk();

  const sourceNodes = assets
    .filter((a) => a.exposure === "internet-facing")
    .map((a) => a.id);

  function findPaths(start: string, visited = new Set<string>()): string[][] {
    if (visited.has(start)) return [];
    visited.add(start);

    const next = edgesMap.get(start) ?? [];
    if (next.length === 0) {
      visited.delete(start);
      return [[start]];
    }

    const paths: string[][] = [];
    for (const node of next) {
      const tails = findPaths(node, visited);
      for (const tail of tails) {
        paths.push([start, ...tail]);
      }
    }

    visited.delete(start);
    return paths;
  }

  const computedPaths = sourceNodes
    .flatMap((source) => findPaths(source))
    .filter((path) => path.length > 1)
    .map((path) => {
      const score = path.reduce((sum, node) => {
        const asset = assets.find((a) => a.id === node);
        return sum + (asset?.aggregatedRisk ?? 0);
      }, 0);
      return {
        path,
        score: Math.round(score * 10) / 10,
        narrative: path.map((node, idx) => `${idx + 1}. ${node}`).join(" → "),
      };
    })
    .sort((a, b) => b.score - a.score);

  return computedPaths;
}

export function getRecommendations() {
  const report = getVulnerabilityReport();

  const recommendations = report.vulnerabilities
    .sort((a, b) => b.cvss - a.cvss)
    .slice(0, 15)
    .map((v, i) => ({
      id: `${v.id}-rec`,
      assetId: v.assetId,
      assetHostname: v.assetHostname,
      recommendation: `Patch ${v.cveId} on ${v.assetHostname} (${v.cvss} CVSS, ${v.severity.toUpperCase()})`,
      priority: v.severity === "critical" ? 1 : v.severity === "high" ? 2 : v.severity === "medium" ? 3 : 4,
      rationale: `Address the ${v.severity} risk finding for ${v.cveId}.`,
    }));

  const prioritized = recommendations.sort((a, b) => a.priority - b.priority);

  return prioritized;
}

export function getScanConfigDefaults() {
  return {
    ipRange: "10.0.0.0/24",
    schedule: "Daily",
    scanType: "Full",
  };
}

export type NetworkLegendItem = {
  assetId: string;
  hostname: string;
  segment: string;
  vlan: number;
  subnet: string;
  exposure: string;
  criticality: string;
  risk: number;
};

export type NetworkLegend = {
  summary: { totalDevices: number; totalVlans: number; networks: Array<{ vlan: number; subnet: string; devices: number }> };
  nodes: NetworkLegendItem[];
};

export function getNetworkLegend(): NetworkLegend {
  const assets = getAssetsWithRisk();
  const vlanMap: Record<string, { vlan: number; subnet: string }> = {
    dmz: { vlan: 100, subnet: "10.0.100.0/24" },
    core: { vlan: 10, subnet: "10.0.10.0/24" },
    app: { vlan: 20, subnet: "10.0.20.0/24" },
    user: { vlan: 30, subnet: "10.0.30.0/24" },
    edge: { vlan: 1, subnet: "10.0.1.0/24" },
    switch: { vlan: 40, subnet: "10.0.40.0/24" },
  };

  const nodes = assets.map((asset) => {
    const vl = vlanMap[asset.segment] ?? { vlan: 999, subnet: "0.0.0.0/0" };
    return {
      assetId: asset.id,
      hostname: asset.hostname,
      segment: asset.segment,
      vlan: vl.vlan,
      subnet: vl.subnet,
      exposure: asset.exposure,
      criticality: asset.criticality,
      risk: asset.aggregatedRisk,
    };
  });

  const networkTable = Object.values(
    nodes.reduce((acc, node) => {
      const key = `${node.vlan}-${node.subnet}`;
      if (!acc[key]) acc[key] = { vlan: node.vlan, subnet: node.subnet, devices: 0 };
      acc[key].devices += 1;
      return acc;
    }, {} as Record<string, { vlan: number; subnet: string; devices: number }>),
  );

  return {
    summary: {
      totalDevices: nodes.length,
      totalVlans: new Set(nodes.map((node) => node.vlan)).size,
      networks: networkTable,
    },
    nodes,
  };
}


