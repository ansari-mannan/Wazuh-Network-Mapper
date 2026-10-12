// Small building blocks of the report: severity chips, per-severity counts,
// the CVE table, configuration findings, remediation lists and sections.
import React, { useState } from 'react';
import { EuiButtonEmpty, EuiHorizontalRule, EuiLink, EuiText, EuiTitle } from '@elastic/eui';
import { GraphNode } from '../../../common';
import { RISK_META, RiskLevel } from '../../lib/risk';
import { unscoredReason } from '../../lib/deviceCveText';
import { AssetCve, capCves, RemediationAction, Severity, SEVERITIES, SplitCounts } from '../../lib/report';
import { SEV_META } from './format';

const SCREEN_CVES = 10; // worst CVEs shown per asset before "show all"

// Severity/risk shown as a colour AND a word (never colour alone).
export function Chip({ color, label }: { color: string; label: string }) {
  return (
    <span className="vmChip">
      <span className="vmChip__dot" style={{ backgroundColor: color }} />
      {label}
    </span>
  );
}

export const riskChip = (level: RiskLevel) => <Chip color={RISK_META[level].color} label={RISK_META[level].label} />;

// Per-severity counts as small chips, within one confidence.
export function CountRow({ label, counts }: { label: string; counts: Record<Severity, number> }) {
  const parts = SEVERITIES.filter((s) => counts[s] > 0);
  if (!parts.length) return null;
  return (
    <div className="vmCountRow">
      <span className="vmCountRow__label">{label}:</span>
      {parts.map((s) => (
        <span key={s} className="vmCountChip">
          <Chip color={SEV_META[s].color} label={`${counts[s]} ${SEV_META[s].label.toLowerCase()}`} />
        </span>
      ))}
    </div>
  );
}

export function CountsSplit({ counts, node }: { counts: SplitCounts; node: GraphNode }) {
  // An unscored host with no CVEs is unknown, not clean: say why instead.
  const why = node.kind === 'endpoint' && node.risk_score === null ? unscoredReason(node) : '';
  if (counts.total === 0) return <EuiText size="xs" color="subdued"><p className="vmNoCves">{why || 'No CVEs match the current filters.'}</p></EuiText>;
  return (
    <>
      <CountRow label="Confirmed" counts={counts.confirmed} />
      <CountRow label="Potential" counts={counts.potential} />
    </>
  );
}

export function CveTable({ cves, cap, expandAll }: { cves: AssetCve[]; cap: number; expandAll: boolean }) {
  const [open, setOpen] = useState(false);
  const { shown, total, capped } = capCves(cves, cap);
  if (!total) return null;
  const showing = expandAll || open ? shown.length : Math.min(SCREEN_CVES, shown.length);
  const rows = shown.slice(0, showing);
  return (
    <div className="vmCveTableWrap">
      <table className="vmTable vmCveTable">
        <thead>
          <tr><th>Severity</th><th>CVE</th><th>CVSS</th><th>Package</th><th>Confidence</th></tr>
        </thead>
        <tbody>
          {rows.map((c) => (
            <tr key={c.cve}>
              <td><Chip color={SEV_META[c.severity].color} label={SEV_META[c.severity].label} /></td>
              <td>{c.reference ? <EuiLink href={c.reference} target="_blank">{c.cve}</EuiLink> : c.cve}</td>
              <td>{c.cvss ?? '—'}{c.cvss != null && c.cvss_version ? ` (v${c.cvss_version})` : ''}</td>
              <td>{c.package || '—'}</td>
              <td>{c.confidence === 'confirmed' ? 'Confirmed' : 'Potential'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {capped ? (
        <EuiText size="xs" color="subdued">
          <p>Showing the {cap} worst of {total}; narrow the severity filter for fewer.</p>
        </EuiText>
      ) : (
        shown.length > SCREEN_CVES && !expandAll && (
          <EuiButtonEmpty size="xs" className="vmScreenOnly" onClick={() => setOpen((v) => !v)}>
            {open ? 'Show fewer' : `Show all ${shown.length}`}
          </EuiButtonEmpty>
        )
      )}
    </div>
  );
}

export function ConfigFindings({ node }: { node: GraphNode }) {
  const findings = node.kind === 'device' ? node.config_findings || [] : [];
  if (!findings.length) return null;
  return (
    <div className="vmConfigFindings">
      <EuiText size="xs"><strong>Configuration findings</strong></EuiText>
      {findings.map((f) => {
        const ref = f.references?.[0];
        return (
          <div key={f.id} className="vmConfigFinding">
            <div className="vmConfigFinding__head">
              <Chip color={f.severity ? SEV_META[f.severity].color : SEV_META.unknown.color} label={f.severity ? SEV_META[f.severity].label : 'Advisory'} />
              <span className="vmConfigFinding__title">{f.title}{ref?.category ? ` · ${ref.category}` : ''}</span>
            </div>
            <div className="vmConfigFinding__why">
              <EuiText size="xs" color="subdued"><p>{f.why}</p></EuiText>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function Remediation({ actions }: { actions: RemediationAction[] }) {
  if (!actions.length) return <EuiText size="xs" color="subdued"><p>No actions to recommend from the data.</p></EuiText>;
  return (
    <ol className="vmRemediation">
      {actions.map((a, i) => (
        <li key={i}>
          {a.category ? <strong>{a.category}: </strong> : null}
          {a.text}
          {a.reference && (
            <>
              {' '}
              <EuiLink href={a.reference.url} target="_blank">{a.reference.title}</EuiLink>
            </>
          )}
        </li>
      ))}
    </ol>
  );
}

export function Section({ title, children, className }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <section className={`vmReportSection ${className || ''}`}>
      <EuiTitle size="m"><h2>{title}</h2></EuiTitle>
      <EuiHorizontalRule margin="s" />
      {children}
    </section>
  );
}
