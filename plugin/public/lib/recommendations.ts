import {
  AttackPathsDoc,
  GraphResponse,
  RecommendationStatus,
  RecommendationsFile,
  VulnerabilitiesDoc,
} from '../../common';
import {
  AssetReport,
  buildAssetReports,
  COVERAGE_GUIDANCE,
  CVE_GUIDANCE,
  Severity,
  SEVERITIES,
} from './report';

// A network-wide, prioritised action plan: every asset's honest recommended
// action, deduplicated across assets into distinct items, each listing the
// assets it affects. It reuses report.ts's logic and wording and invents
// nothing. Kept free of React/theme imports so it unit-tests on its own.

export type RecommendationSource = 'config' | 'firmware' | 'os-updates' | 'service' | 'coverage';

export type AffectedAsset = { id: string; name: string; onPath: boolean; routesThrough: number };

export type Recommendation = {
  key: string; // stable across rescans
  title: string; // short action label
  action: string; // the honest remediation text
  severity: Severity | null; // what it addresses; null = informational
  source: RecommendationSource;
  reference: { title: string; url: string } | null;
  category: string | null; // DISA CAT I/II/III for a config finding
  affected: AffectedAsset[];
  affectedCount: number;
  onPathCount: number;
  status: RecommendationStatus;
};

// Worst-first; null (advisory/informational) last. Matches report.ts's rank.
const sevRank = (s: Severity | null): number => (s ? SEVERITIES.length - SEVERITIES.indexOf(s) : 0);

// The worse of two severities (null = none).
const worseSeverity = (a: Severity | null, b: Severity | null): Severity | null =>
  sevRank(a) >= sevRank(b) ? a : b;

const affectedOf = (r: AssetReport): AffectedAsset => ({
  id: r.id,
  name: r.name,
  onPath: r.onPath,
  routesThrough: r.routesThrough,
});

// The CVE bucket an asset with CVEs falls into (key/title/wording), mirroring
// remediationActions: devices → firmware, managed hosts → OS updates, every
// other version-matched endpoint (nmap or SNMP) → the detected-service bucket.
function cveBucket(r: AssetReport): { key: string; title: string; source: RecommendationSource; action: string } | null {
  if (r.cves.length === 0) return null;
  if (r.node.kind === 'device') return { key: 'cve:firmware', title: 'Update device firmware', source: 'firmware', action: CVE_GUIDANCE.firmware };
  if (r.managed) return { key: 'cve:os-updates', title: 'Apply OS and package updates', source: 'os-updates', action: CVE_GUIDANCE.os };
  return { key: 'cve:service', title: 'Update detected services', source: 'service', action: CVE_GUIDANCE.service };
}

export function buildRecommendations(
  graph: GraphResponse,
  vulns: VulnerabilitiesDoc,
  attackPaths: AttackPathsDoc | null,
  file: RecommendationsFile | null,
  // offline hosts are not counted as affected (topology/inactive.ts's rule)
  offline: ReadonlySet<string> = new Set()
): Recommendation[] {
  const reports = buildAssetReports(graph, vulns, attackPaths, offline);
  const recs = new Map<string, Recommendation>();

  // Accumulate the affected asset into a recommendation, creating it on first
  // sight. A later asset never changes the item's text, only its severity
  // (kept worst) and its affected list.
  const add = (
    base: Omit<Recommendation, 'affected' | 'affectedCount' | 'onPathCount' | 'status'>,
    r: AssetReport
  ) => {
    const existing = recs.get(base.key);
    if (existing) {
      existing.affected.push(affectedOf(r));
      existing.severity = worseSeverity(existing.severity, base.severity);
    } else {
      recs.set(base.key, { ...base, affected: [affectedOf(r)], affectedCount: 0, onPathCount: 0, status: 'open' });
    }
  };

  for (const r of reports) {
    // Configuration findings — keep finding.id for a stable key, use the
    // stored remediation text verbatim.
    for (const f of r.configFindings) {
      const ref = f.references?.[0];
      add(
        {
          key: `config:${f.id}`,
          title: f.title,
          action: f.remediation,
          severity: f.severity, // null → Advisory
          source: 'config',
          reference: ref ? { title: ref.title, url: ref.url } : null,
          category: ref?.category ?? null,
        },
        r
      );
    }

    // CVEs — the asset's generic bucket, severity = its worst CVE.
    const bucket = cveBucket(r);
    if (bucket) {
      add({ ...bucket, severity: r.cves[0].severity, reference: null, category: null }, r);
    }

    // Coverage — unmanaged endpoints.
    if (r.node.kind === 'endpoint' && r.node.unmanaged) {
      add(
        {
          key: 'coverage:agents',
          title: 'Deploy Wazuh agents',
          action: COVERAGE_GUIDANCE,
          severity: null,
          source: 'coverage',
          reference: null,
          category: null,
        },
        r
      );
    }
  }

  const out = [...recs.values()];
  for (const rec of out) {
    rec.affectedCount = rec.affected.length;
    rec.onPathCount = rec.affected.filter((a) => a.onPath).length;
    rec.status = file?.statuses[rec.key]?.status ?? 'open';
  }

  // Worst-first: severity, then more affected, then more on-path, then key.
  return out.sort(
    (a, b) =>
      sevRank(b.severity) - sevRank(a.severity) ||
      b.affectedCount - a.affectedCount ||
      b.onPathCount - a.onPathCount ||
      a.key.localeCompare(b.key)
  );
}

export function recommendationProgress(recs: Recommendation[]): {
  total: number;
  addressed: number;
  byStatus: Record<RecommendationStatus, number>;
} {
  const byStatus: Record<RecommendationStatus, number> = { open: 0, in_progress: 0, done: 0, accepted_risk: 0 };
  for (const r of recs) byStatus[r.status] += 1;
  return { total: recs.length, addressed: byStatus.done + byStatus.accepted_risk, byStatus };
}
