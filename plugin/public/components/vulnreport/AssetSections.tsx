// One asset in the report's findings: a ranked block (most-vulnerable mode)
// or the full detail of the single asset picked.
import React from 'react';
import { EuiBadge, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { GraphNode } from '../../../common';
import { AssetReport } from '../../lib/report';
import { roleLabel } from '../../lib/roleLabel';
import { exposureText, ovssLine, tierReason } from '../../lib/ovssText';
import { TierReasonLine, TierTip } from '../layout/TierReason';
import { TIERS } from '../../lib/risk';
import { ConfigFindings, CountsSplit, CveTable, riskChip } from './parts';

interface AssetProps {
  report: AssetReport;
  cap: number;
  expandAll: boolean;
}

function assetMeta(r: AssetReport) {
  const n = r.node;
  const role = n.role ? roleLabel(n.role, n.kind) : n.kind;
  return `${role}${n.ip ? ` · ${n.ip}` : ''} · ${r.managed ? 'Managed' : 'Unmanaged'}`;
}

function AssetHead({ report, title }: { report: AssetReport; title: React.ReactElement }) {
  // the chip shows the tier unless a configuration finding outranks it
  const why = report.level === report.node.node_tier ? tierReason(report.node.node_tier, report.cves) : null;
  return (
    <>
      <div className="vmAssetBlock__head">
        {title}
        <TierTip why={why}>{riskChip(report.level)}</TierTip>
        {report.onPath && <EuiBadge color="hollow">On an attack path</EuiBadge>}
      </div>
      <TierReasonLine why={why} />
    </>
  );
}

// The asset's OVSS: score and tier (or why it has none), its tier histogram
// and the inputs it was scored with.
function OvssLine({ node, tiers }: { node: GraphNode; tiers: AssetReport['tiers'] }) {
  const parts = [ovssLine(node)];
  if (node.ovss_status === 'assessed') parts.push(TIERS.map((t) => `${t} ${tiers[t]}`).join(' · '));
  if (node.ovss_status) {
    parts.push(`exposure ${exposureText(node.exposure, node.exposure_flag)}`);
    parts.push(`dependency ${node.dependency ?? 0}`);
    parts.push(`importance ${node.importance || 'not marked'}`);
  }
  return <EuiText size="xs" data-test-subj="vmAssetOvss"><p>{parts.join(' · ')}</p></EuiText>;
}

// The counts, the CVE table and the configuration findings, shared by both views.
function AssetFindings({ report, cap, expandAll }: AssetProps) {
  return (
    <>
      <OvssLine node={report.node} tiers={report.tiers} />
      <CountsSplit counts={report.counts} node={report.node} />
      <EuiSpacer size="xs" />
      <CveTable cves={report.cves} cap={cap} expandAll={expandAll} />
      <ConfigFindings node={report.node} />
    </>
  );
}

export function AssetBlock({ report, cap, expandAll }: AssetProps) {
  return (
    <div className="vmAssetBlock">
      <AssetHead report={report} title={<EuiTitle size="xs"><h4>{report.name}</h4></EuiTitle>} />
      <EuiText size="xs" color="subdued"><p>{assetMeta(report)}</p></EuiText>
      <EuiSpacer size="xs" />
      <AssetFindings report={report} cap={cap} expandAll={expandAll} />
    </div>
  );
}

function identityRows(n: GraphNode): Array<[string, string]> {
  const rows: Array<[string, string]> = [];
  const add = (k: string, v?: string | null) => { if (v) rows.push([k, v]); };
  add('Vendor', n.vendor);
  add('Model', n.model);
  add('Firmware', n.firmware);
  add('Serial', n.serial);
  if (n.kind === 'endpoint') {
    add('Manufacturer (from MAC)', n.mac_vendor);
    add('Device hint', n.device_hint);
  }
  add('IP', n.ip);
  add('MAC', n.mac);
  return rows;
}

function OpenPortsTable({ node }: { node: GraphNode }) {
  const ports = node.kind === 'endpoint' ? node.open_ports || [] : [];
  if (!ports.length) return null;
  return (
    <>
      <EuiSpacer size="s" />
      <EuiText size="xs"><strong>Open ports and detected services</strong></EuiText>
      <table className="vmTable">
        <thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
        <tbody>
          {ports.map((p) => (
            <tr key={`${p.protocol}/${p.port}`}>
              <td>{p.port}/{p.protocol}</td><td>{p.service || '—'}</td><td>{p.product || '—'}</td><td>{p.version || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

export function AssetDetail({ report, cap, expandAll }: AssetProps) {
  return (
    <div className="vmAssetBlock">
      <AssetHead report={report} title={<EuiTitle size="s"><h3>{report.name}</h3></EuiTitle>} />
      <EuiText size="xs" color="subdued"><p>{assetMeta(report)}</p></EuiText>
      <EuiSpacer size="s" />
      <table className="vmTable vmKeyValue">
        <tbody>
          {identityRows(report.node).map(([k, v]) => (<tr key={k}><th>{k}</th><td>{v}</td></tr>))}
        </tbody>
      </table>
      <OpenPortsTable node={report.node} />
      <EuiSpacer size="s" />
      <AssetFindings report={report} cap={cap} expandAll={expandAll} />
    </div>
  );
}
