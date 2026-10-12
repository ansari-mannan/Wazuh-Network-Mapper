import {
  AttackPathsDoc,
  ConfigFinding,
  GraphNode,
  GraphResponse,
  VulnerabilitiesDoc,
} from '../../common';
import {
  displayRiskLevel,
  nodeRiskScore,
  RiskLevel,
  riskLevel,
} from './riskRule';

// The vulnerability report's data model. Everything here is derived from the
// three files the scan produced (graph, vulnerabilities, attack paths); nothing
// is invented. Kept free of theme/React imports so it is unit tested on its own.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown'];

export type Confidence = 'confirmed' | 'potential';

const SEVERITY_RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, unknown: 1 };
const LEVEL_RANK: Record<RiskLevel, number> = { critical: 4, high: 3, medium: 2, low: 1, unscored: 0 };

// A CVE's severity band. The CVSS score is the one rule (as everywhere else); a
// CVE with no score but a qualitative severity falls back to that word.
export function severityBand(cvss: number | null, severity?: string | null): Severity {
  const level = riskLevel(cvss);
  if (level !== 'unscored') return level;
  const word = (severity || '').toLowerCase();
  return (['critical', 'high', 'medium', 'low'] as Severity[]).includes(word as Severity)
    ? (word as Severity)
    : 'unknown';
}

export type AssetCve = {
  cve: string;
  cvss: number | null;
  cvss_version: string | null;
  severity: Severity;
  description: string | null;
  reference: string | null;
  confidence: Confidence;
  package: string | null;
  version: string | null;
};

export type SeverityCounts = Record<Severity, number>;
const zeroCounts = (): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });

export type SplitCounts = { confirmed: SeverityCounts; potential: SeverityCounts; total: number };

export type AssetReport = {
  node: GraphNode;
  id: string;
  name: string;
  managed: boolean; // reports from a Wazuh agent
  displayRisk: RiskLevel;
  counts: SplitCounts;
  cves: AssetCve[]; // distinct, worst-first
  configFindings: ConfigFinding[];
  onPath: boolean;
  routesThrough: number;
};

/** A node's own CVEs are confirmed only when a Wazuh agent reports from it. */
function confidenceOf(node: GraphNode): Confidence {
  return node.kind === 'endpoint' && !node.unmanaged ? 'confirmed' : 'potential';
}

/** The worst DISA/STIG severity among a node's configuration findings. */
function worstConfigSeverity(node: GraphNode): 'high' | 'medium' | 'low' | null {
  const findings = node.kind === 'device' ? node.config_findings : undefined;
  let worst: 'high' | 'medium' | 'low' | null = null;
  for (const f of findings || []) {
    if (f.severity === 'high') return 'high';
    if (f.severity === 'medium') worst = worst === 'low' || worst === null ? 'medium' : worst;
    else if (f.severity === 'low' && worst === null) worst = 'low';
  }
  return worst;
}

function nameOf(node: GraphNode): string {
  return node.hostname || node.ip || node.node_id;
}

/**
 * Build one report row per graph node (devices and endpoints), resolving each
 * node's full distinct CVE list from vulnerabilities.json and the shared
 * catalogue, with the confirmed/potential confidence and the severity counts.
 * Rows are unfiltered; ranking and filters are applied afterwards.
 */
export function buildAssetReports(
  graph: GraphResponse,
  vulns: VulnerabilitiesDoc,
  attackPaths: AttackPathsDoc | null,
  // offline hosts (topology/inactive.ts's rule) are not assessed at all
  offline: ReadonlySet<string> = new Set()
): AssetReport[] {
  const routesThrough = new Map<string, number>();
  for (const a of attackPaths?.per_asset || []) routesThrough.set(a.id, a.routes_through);

  const reports: AssetReport[] = [];
  for (const node of graph.nodes) {
    if (node.kind !== 'device' && node.kind !== 'endpoint') continue;
    if (offline.has(node.node_id)) continue;
    const confidence = confidenceOf(node);
    const entry = vulns.hosts[node.node_id];

    // Distinct CVEs for this asset, resolved through the catalogue.
    const seen = new Set<string>();
    const cves: AssetCve[] = [];
    for (const f of entry?.findings || []) {
      if (!f.cve || seen.has(f.cve)) continue;
      seen.add(f.cve);
      const cat = vulns.cves[f.cve];
      cves.push({
        cve: f.cve,
        cvss: cat?.cvss ?? null,
        cvss_version: cat?.cvss_version ?? null,
        severity: severityBand(cat?.cvss ?? null, cat?.severity),
        description: cat?.description ?? null,
        reference: cat?.reference ?? null,
        confidence,
        package: f.package,
        version: f.version,
      });
    }
    // Worst-first: by CVSS (nulls last), then CVE id for a stable order.
    cves.sort(
      (a, b) =>
        (b.cvss ?? -1) - (a.cvss ?? -1) ||
        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
        a.cve.localeCompare(b.cve)
    );

    const counts: SplitCounts = { confirmed: zeroCounts(), potential: zeroCounts(), total: cves.length };
    for (const c of cves) counts[c.confidence][c.severity] += 1;

    reports.push({
      node,
      id: node.node_id,
      name: nameOf(node),
      managed: confidence === 'confirmed',
      displayRisk: displayRiskLevel(nodeRiskScore(node), worstConfigSeverity(node)),
      counts,
      cves,
      configFindings: (node.kind === 'device' ? node.config_findings : undefined) || [],
      onPath: (routesThrough.get(node.node_id) || 0) > 0,
      routesThrough: routesThrough.get(node.node_id) || 0,
    });
  }
  return reports;
}

/**
 * Worst-first ranking: by displayed risk level, then confirmed-critical count,
 * then total CVE count, then name (stable). Ranking uses the asset's intrinsic
 * figures, not the active filters.
 */
export function rankAssetReports(reports: AssetReport[]): AssetReport[] {
  return reports.slice().sort(
    (a, b) =>
      LEVEL_RANK[b.displayRisk] - LEVEL_RANK[a.displayRisk] ||
      b.counts.confirmed.critical - a.counts.confirmed.critical ||
      b.counts.total - a.counts.total ||
      a.name.localeCompare(b.name)
  );
}

export type ReportFilters = {
  severities: Severity[]; // which CVE severities to include
  confidence: 'all' | 'confirmed' | 'potential';
  onPath: boolean; // only assets a route passes through
};

export const ALL_FILTERS: ReportFilters = {
  severities: SEVERITIES.slice(),
  confidence: 'all',
  onPath: false,
};

/** A copy of the row with its CVEs narrowed to the filters and counts recomputed. */
export function filterAssetReport(report: AssetReport, filters: ReportFilters): AssetReport {
  const sev = new Set(filters.severities);
  const cves = report.cves.filter(
    (c) => sev.has(c.severity) && (filters.confidence === 'all' || c.confidence === filters.confidence)
  );
  const counts: SplitCounts = { confirmed: zeroCounts(), potential: zeroCounts(), total: cves.length };
  for (const c of cves) counts[c.confidence][c.severity] += 1;
  return { ...report, cves, counts };
}

/** Rank, then filter: drop on-path mismatches and rows left with no CVEs. */
export function reportAssets(reports: AssetReport[], filters: ReportFilters): AssetReport[] {
  const narrow = filters.severities.length < SEVERITIES.length || filters.confidence !== 'all';
  return rankAssetReports(reports)
    .filter((r) => !filters.onPath || r.onPath)
    .map((r) => filterAssetReport(r, filters))
    // A severity/confidence filter hides rows with nothing left to show; with
    // no such filter an asset with no CVEs still appears (its config findings).
    .filter((r) => !narrow || r.cves.length > 0);
}

/** Cap a CVE list for the PDF: the worst `cap`, with the full total. */
export function capCves(cves: AssetCve[], cap: number): { shown: AssetCve[]; total: number; capped: boolean } {
  return { shown: cves.slice(0, cap), total: cves.length, capped: cves.length > cap };
}

// --- Remediation (honest only: either stored text, or generic guidance) ---

export type RemediationAction = {
  severity: Severity | null; // what it addresses, for ordering; null = informational
  text: string;
  source: 'config' | 'cve' | 'coverage' | 'path';
  reference?: { title: string; url: string } | null;
  category?: string | null; // DISA CAT I/II/III for a config finding
};

// The honest, generic CVE/coverage wording, in one place so the per-asset
// report and the network-wide recommendations say the same thing. None of it
// names an invented fixed version; each line states why the finding is only
// potential. The per-asset report may append factual detail (package names).
export const CVE_GUIDANCE = {
  firmware: "Confirm the running version and apply the vendor's latest firmware; the findings are version-matched and not confirmed on the device.",
  os: 'Apply operating-system and package updates.',
  service: 'Verify the service and update it; detected by version only.',
  endpoint: 'Confirm the running version and update it; the findings are version-matched only.',
} as const;
export const COVERAGE_GUIDANCE =
  'Deploy a Wazuh agent or document this asset; its software and vulnerabilities are otherwise unknown.';

/** Package names carrying the most critical (then high, then any) CVEs. */
function worstPackages(cves: AssetCve[], limit = 2): string[] {
  const score = new Map<string, number>();
  for (const c of cves) {
    if (!c.package) continue;
    score.set(c.package, (score.get(c.package) || 0) + SEVERITY_RANK[c.severity]);
  }
  return [...score.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, limit).map((e) => e[0]);
}

/**
 * A prioritised, honest list of recommended actions for one asset, drawn only
 * from data we have. Configuration findings use their stored remediation text
 * verbatim; CVE guidance is generic and never names an invented fixed version.
 */
export function remediationActions(report: AssetReport): RemediationAction[] {
  const actions: RemediationAction[] = [];
  const { node } = report;

  // 1) Configuration findings — the checklist's own remediation text, verbatim.
  for (const f of report.configFindings) {
    const ref = f.references?.[0];
    actions.push({
      severity: f.severity || 'low',
      text: f.remediation,
      source: 'config',
      category: ref?.category ?? null,
      reference: ref ? { title: ref.title, url: ref.url } : null,
    });
  }

  // 2) CVEs — one generic line by asset kind, if the asset has any CVEs.
  if (report.cves.length > 0) {
    const worst = report.cves[0].severity;
    if (node.kind === 'device') {
      actions.push({ severity: worst, source: 'cve', text: CVE_GUIDANCE.firmware });
    } else if (report.managed) {
      const n = report.cves.length;
      const pkgs = worstPackages(report.cves);
      const where = pkgs.length ? ` ${n} finding${n === 1 ? '' : 's'} affect ${pkgs.join(' and ')}.` : '';
      actions.push({ severity: worst, source: 'cve', text: `${CVE_GUIDANCE.os}${where}` });
    } else if (node.kind === 'endpoint' && node.cve_lookup?.source === 'nmap') {
      actions.push({ severity: worst, source: 'cve', text: CVE_GUIDANCE.service });
    } else {
      actions.push({ severity: worst, source: 'cve', text: CVE_GUIDANCE.endpoint });
    }
  }

  // 3) Unmanaged host — its software is otherwise unknown.
  if (node.kind === 'endpoint' && node.unmanaged) {
    actions.push({ severity: null, source: 'coverage', text: COVERAGE_GUIDANCE });
  }

  // Order by severity of what each action addresses (informational last).
  actions.sort((a, b) => (b.severity ? SEVERITY_RANK[b.severity] : 0) - (a.severity ? SEVERITY_RANK[a.severity] : 0));

  // 4) On an attack path — note it, last.
  if (report.onPath) {
    const n = report.routesThrough;
    actions.push({
      severity: null,
      source: 'path',
      text: `This asset lies on ${n} exposure path${n === 1 ? '' : 's'}; addressing the above reduces them.`,
    });
  }
  return actions;
}

// --- Executive summary (whole-scan figures, unfiltered) ---

export type ExecutiveSummary = {
  totalAssets: number;
  managed: number;
  totalHosts: number;
  counts: SplitCounts; // severity split across every asset
  onPathAssets: number;
  worstAssets: string[]; // names of the handful of worst assets
};

// Host figures come from the rows themselves, so offline hosts left out of the
// report are left out of the summary too.
export function executiveSummary(reports: AssetReport[], worstNames = 5): ExecutiveSummary {
  const counts: SplitCounts = { confirmed: zeroCounts(), potential: zeroCounts(), total: 0 };
  for (const r of reports) {
    for (const sev of SEVERITIES) {
      counts.confirmed[sev] += r.counts.confirmed[sev];
      counts.potential[sev] += r.counts.potential[sev];
    }
    counts.total += r.counts.total;
  }
  const hosts = reports.filter((r) => r.node.kind === 'endpoint');
  return {
    totalAssets: reports.length,
    managed: hosts.filter((r) => r.managed).length,
    totalHosts: hosts.length,
    counts,
    onPathAssets: reports.filter((r) => r.onPath).length,
    worstAssets: rankAssetReports(reports).slice(0, worstNames).map((r) => r.name),
  };
}

/**
 * The "Most at risk (by CVE count)" chart: the assets with the most distinct
 * CVEs, most first, so the bar order matches the bar lengths (ties by name).
 */
export function mostCves(reports: AssetReport[], limit = 7): AssetReport[] {
  return reports
    .filter((r) => r.counts.total > 0)
    .sort((a, b) => b.counts.total - a.counts.total || a.name.localeCompare(b.name))
    .slice(0, limit);
}

/** The distinct address ranges (/24s) seen among the graph's IPs, for the cover. */
export function addressRanges(graph: GraphResponse): string[] {
  const nets = new Set<string>();
  for (const n of graph.nodes) {
    const ip = n.ip;
    if (!ip) continue;
    const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.\d+$/);
    if (m) nets.add(`${m[1]}.${m[2]}.${m[3]}.0/24`);
  }
  return [...nets].sort();
}
