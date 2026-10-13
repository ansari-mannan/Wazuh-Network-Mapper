// The sections of the printed report, in order: cover, executive summary,
// methodology, findings and remediation.
import React from 'react';
import { EuiLink, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { AttackPathsDoc, GraphNode, GraphResponse } from '../../../common';
import { NodeLevel } from '../../lib/risk';
import { addressRanges, AssetReport, ExecutiveSummary, remediationActions } from '../../lib/report';
import { AssetBlock, AssetDetail } from './AssetSections';
import { MostAtRisk, SeverityBar, StatBand, TierRow } from './charts';
import { prettyDate, TOOL } from './format';
import { CountRow, Remediation, Section } from './parts';
import { ReportMode } from './ReportControls';

export function Cover({ graph, org, exec }: { graph: GraphResponse; org: string; exec: ExecutiveSummary | null }) {
  return (
    <section className="vmReportSection vmCover">
      <EuiTitle size="l"><h1>Vulnerability Assessment Report</h1></EuiTitle>
      <EuiSpacer size="s" />
      <EuiText><p className="vmCover__org">{org}</p></EuiText>
      <EuiSpacer size="m" />
      <table className="vmTable vmKeyValue">
        <tbody>
          <tr><th>Scan date</th><td>{prettyDate(graph.metadata.scan_time)}</td></tr>
          <tr><th>Scope</th><td>{exec?.totalAssets ?? 0} assets{addressRanges(graph).length ? ` · ${addressRanges(graph).join(', ')}` : ''}</td></tr>
          <tr><th>Tool</th><td>{TOOL}</td></tr>
        </tbody>
      </table>
      {exec && exec.counts.total > 0 && (
        <div className="vmCover__chart">
          <EuiText size="xs" color="subdued"><p>Findings by severity</p></EuiText>
          <SeverityBar counts={exec.counts} split={false} />
        </div>
      )}
    </section>
  );
}

interface SummaryProps {
  exec: ExecutiveSummary | null;
  offline: GraphNode[];
  topRisk: Array<{ name: string; total: number; level: NodeLevel }>;
}

export function ExecutiveSummarySection({ exec, offline, topRisk }: SummaryProps) {
  return (
    <Section title="Executive summary">
      {exec && (
        <>
          <StatBand exec={exec} />
          <EuiSpacer size="m" />
          <EuiText size="s">
            <p>
              This assessment covers <strong>{exec.totalAssets}</strong> assets. A Wazuh agent reports from{' '}
              <strong>{exec.managed}</strong> of <strong>{exec.totalHosts}</strong> hosts, so findings on those hosts
              are confirmed; findings elsewhere are potential (matched by software version).{' '}
              <strong>{exec.onPathAssets}</strong> asset{exec.onPathAssets === 1 ? ' lies' : 's lie'} on an attack path.
            </p>
          </EuiText>
          {offline.length > 0 && (
            <EuiText size="xs" color="subdued" data-test-subj="vmOfflineHosts">
              <p>
                {offline.length} offline host{offline.length === 1 ? '' : 's'} not assessed:{' '}
                {offline.map((n) => n.hostname || n.ip || n.node_id).join(', ')}
              </p>
            </EuiText>
          )}
          <EuiSpacer size="m" />
          <div className="vmChartBlock">
            <EuiText size="xs"><strong>Findings by severity (confirmed vs potential)</strong></EuiText>
            <EuiSpacer size="xs" />
            <SeverityBar counts={exec.counts} />
            <EuiSpacer size="xs" />
            <div className="vmExecCounts">
              <CountRow label="Confirmed" counts={exec.counts.confirmed} />
              <CountRow label="Potential" counts={exec.counts.potential} />
              <TierRow tiers={exec.tiers} />
            </div>
          </div>
          {topRisk.length > 0 && (
            <>
              <EuiSpacer size="l" />
              <div className="vmChartBlock">
                <EuiText size="xs"><strong>Most CVEs</strong></EuiText>
                <EuiSpacer size="xs" />
                <MostAtRisk items={topRisk} />
              </div>
            </>
          )}
        </>
      )}
    </Section>
  );
}

export function Methodology({ attackPaths }: { attackPaths: AttackPathsDoc | null }) {
  const meta = attackPaths?.metadata;
  return (
    <Section title="Methodology and sources">
      <EuiText size="s">
        <p>
          Findings reported by a Wazuh agent on the host are <strong>confirmed</strong>. Findings matched against the
          NVD by software version — network devices, hosts without an agent, and services detected by nmap — are{' '}
          <strong>potential</strong>: a version match does not prove the affected feature is in use. Device
          configuration is checked against DISA STIG and CCSS rules; attack-path likelihood follows NIST IR 7788.
        </p>
        <p><strong>OVSS: how findings are scored and ranked</strong></p>
        <p>
          Each finding (one CVE on one asset) gets an OVSS score from 0 to 10, never above its CVSS base score:
        </p>
        <ul className="vmFormula">
          <li>OVSS = CVSS × Context × ThreatMult</li>
          <li>Context = 0.5 + 0.5 × (Exposure + Dependency) / 2</li>
          <li>ThreatMult = 0.5 + 0.5 × T, where T = 1.0 for a CVE in CISA KEV, else min(EPSS / 0.1, 1.0)</li>
        </ul>
        <p>
          The CVSS score is the CVE&apos;s CNA score, else an ADP&apos;s, else the scanner&apos;s (highest CVSS
          version within each); with none the finding is Unrated. Exposure is 1.0 for the egress router, 0.3 in a
          VLAN no router connects to another, 0.5 otherwise (and 0.5, flagged, when the asset&apos;s VLAN is
          unknown). Dependency is the larger of the share of other assets that depend on it and its marked
          importance (FIPS 199: high 1.0, moderate 0.5, low 0.25). An asset&apos;s OVSS is its highest
          finding&apos;s; assets are ranked by it.
        </p>
        <p>
          Tiers: <strong>P0</strong> at 6.75 and above, <strong>P1</strong> at 4.5, <strong>P2</strong> at 2.5,
          else <strong>P3</strong>. Then, in order: a potential finding not in KEV is capped at P1; a KEV finding on
          the egress router is P0; any KEV finding is at least P1. An asset with nothing found or looked up is
          Unassessed, which is not the same as clean.
        </p>
        <p><strong>OVSS sources</strong></p>
        <ul>
          <li><EuiLink href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank">CISA Known Exploited Vulnerabilities (KEV) catalog</EuiLink></li>
          <li><EuiLink href="https://www.first.org/epss/" target="_blank">FIRST Exploit Prediction Scoring System (EPSS)</EuiLink></li>
          <li><EuiLink href="https://www.cve.org/" target="_blank">CVE records (CNA and ADP scores), CVE Program</EuiLink></li>
        </ul>
        {meta?.reachability?.length ? (
          <>
            <p><strong>Reachability</strong></p>
            <ul>{meta.reachability.map((t, i) => <li key={i}>{t}</li>)}</ul>
          </>
        ) : null}
        {meta?.limits?.length ? (
          <>
            <p><strong>Limitations</strong></p>
            <ul>{meta.limits.map((t, i) => <li key={i}>{t}</li>)}</ul>
          </>
        ) : null}
        {meta?.sources?.length ? (
          <>
            <p><strong>Sources</strong></p>
            <ul>{meta.sources.map((s, i) => <li key={i}><EuiLink href={s.url} target="_blank">{s.title}</EuiLink></li>)}</ul>
          </>
        ) : null}
      </EuiText>
    </Section>
  );
}

interface FindingsProps {
  mode: ReportMode;
  ranked: AssetReport[];
  hiddenCount: number;
  single: AssetReport | null;
  cap: number;
  expandAll: boolean;
}

export function Findings({ mode, ranked, hiddenCount, single, cap, expandAll }: FindingsProps) {
  const assets = mode === 'ranked' ? ranked : single ? [single] : [];
  return (
    <Section title="Findings">
      {mode === 'single' && !single ? (
        <EuiText color="subdued"><p>Pick an asset above to see its detail.</p></EuiText>
      ) : assets.length === 0 ? (
        <EuiText color="subdued"><p>No assets match the current filters.</p></EuiText>
      ) : mode === 'ranked' ? (
        <>
          {ranked.map((r) => (<AssetBlock key={r.id} report={r} cap={cap} expandAll={expandAll} />))}
          {hiddenCount > 0 && (
            <EuiText size="xs" color="subdued"><p>and {hiddenCount} more asset{hiddenCount === 1 ? '' : 's'} (raise Top N to include them).</p></EuiText>
          )}
        </>
      ) : (
        single && <AssetDetail report={single} cap={cap} expandAll={expandAll} />
      )}
    </Section>
  );
}

export function RemediationSection({ assets }: { assets: AssetReport[] }) {
  return (
    <Section title="Remediation">
      {assets.length === 0 ? (
        <EuiText color="subdued"><p>No assets in scope.</p></EuiText>
      ) : (
        assets.map((r) => (
          <div key={r.id} className="vmRemediationAsset">
            <EuiText size="s"><strong>{r.name}</strong></EuiText>
            <Remediation actions={remediationActions(r)} />
          </div>
        ))
      )}
    </Section>
  );
}
