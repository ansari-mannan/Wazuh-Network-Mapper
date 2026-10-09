import React, { ReactNode } from 'react';
import {
  EuiBadge,
  EuiDescriptionList,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutHeader,
  EuiHealth,
  EuiNotificationBadge,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { CveSummary, GraphNode, NodeLiveness } from '../../../common';
import { useGraph } from '../../lib/graph';
import { useLiveness } from '../../lib/liveness';
import { clientCountText, wifiClientText } from '../../lib/wifiText';
import { livenessMethod } from '../../lib/livenessText';
import { hasDeviceFindings, potentialText, staleText, unscoredReason } from '../../lib/deviceCveText';
import { nodeRiskScore, RISK_META, riskLevel, RiskLevel } from '../../lib/risk';
import { ConfigChecks } from './ConfigChecks';
import { iconForRole } from './icons';
import { isOffline, riskLabel } from './nodeStyle';

// Ported from frontend/risk-module/ui/topology/DeviceDetail.tsx to an OUI
// flyout: identity, risk and CVE list (endpoints from Wazuh, devices from NVD),
// configuration checks and port grid for devices.

const EMPTY = '—';

function Section({ title, count, children }: { title: string; count?: number; children: ReactNode }) {
  return (
    <EuiPanel paddingSize="m" hasShadow={false} hasBorder>
      <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiTitle size="xxs">
            <h3>{title}</h3>
          </EuiTitle>
        </EuiFlexItem>
        {count !== undefined && (
          <EuiFlexItem grow={false}>
            <EuiNotificationBadge color="subdued">{count}</EuiNotificationBadge>
          </EuiFlexItem>
        )}
      </EuiFlexGroup>
      <EuiSpacer size="s" />
      {children}
    </EuiPanel>
  );
}

function fields(pairs: Array<[string, ReactNode]>) {
  return pairs.map(([title, value]) => ({
    title,
    description: value === null || value === undefined || value === '' ? EMPTY : value,
  }));
}

// The scanner keeps Windows line breaks as literal "\r\n" text in descriptions.
function cleanDescription(text: string): string {
  return text.replace(/\\r\\n|\\n|\\r/g, '\n').trim();
}

function severityLevel(severity: string | null, cvss: number | null): RiskLevel {
  const s = (severity || '').toLowerCase();
  if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') return s;
  return riskLevel(cvss);
}

// Distinct-CVE counts per band, worst first; "unknown" = CVEs with no score.
const SUMMARY_BANDS: Array<{
  key: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  level: RiskLevel;
  label: string;
}> = [
  { key: 'critical', level: 'critical', label: 'Critical' },
  { key: 'high', level: 'high', label: 'High' },
  { key: 'medium', level: 'medium', label: 'Medium' },
  { key: 'low', level: 'low', label: 'Low' },
  { key: 'unknown', level: 'unscored', label: 'Unknown' },
];

function RiskSummary({ score, summary }: { score: number | null; summary: CveSummary }) {
  return (
    <Section title="Risk">
      <EuiDescriptionList
        type="column"
        compressed
        className="vmFields"
        listItems={fields([
          ['Risk (base score)', riskLabel(score)],
          ['Worst CVE (CVSS)', summary.max_cvss],
        ])}
      />
      <EuiSpacer size="s" />
      <EuiFlexGroup gutterSize="xs" wrap responsive={false} data-test-subj="vmCveCounts">
        {SUMMARY_BANDS.map((b) => {
          const n = summary[b.key];
          return (
            <EuiFlexItem grow={false} key={b.key}>
              <EuiBadge color={n > 0 ? RISK_META[b.level].color : 'hollow'}>
                {b.label} {n}
              </EuiBadge>
            </EuiFlexItem>
          );
        })}
      </EuiFlexGroup>
    </Section>
  );
}

/** "last seen" time for liveness, in the viewer's locale; "never" if not seen. */
export function formatSeen(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

const LIVENESS_HEALTH: Record<string, { color: string; label: string }> = {
  active: { color: 'success', label: 'Active' },
  inactive: { color: 'danger', label: 'Inactive' },
  unknown: { color: 'subdued', label: 'Unknown' },
};

function LivenessValue({ value }: { value: NodeLiveness | undefined }) {
  if (!value) {
    return <EuiHealth color="subdued">Unknown · not checked yet</EuiHealth>;
  }
  const health = LIVENESS_HEALTH[value.state] || LIVENESS_HEALTH.unknown;
  return (
    <span data-test-subj="vmLiveness">
      <EuiHealth color={health.color}>{health.label}</EuiHealth>
      <EuiText size="xs" color="subdued">
        <p>
          last seen {formatSeen(value.last_seen)} · via {livenessMethod(value)}
        </p>
      </EuiText>
    </span>
  );
}

export function DeviceDetail({ node, onClose }: { node: GraphNode; onClose: () => void }) {
  const { graph } = useGraph();
  const nameOf = (id: string) => {
    const other = graph?.nodes.find((n) => n.node_id === id);
    return (other && (other.hostname || other.ip)) || id;
  };
  // An access point shows its client count; a Wi-Fi client its SSID and AP.
  const wifiRows: Array<[string, ReactNode]> = [];
  if (node.kind === 'device' && typeof node.wifi_clients === 'number') {
    wifiRows.push(['Wi-Fi clients', clientCountText(node.wifi_clients)]);
  }
  if (node.kind === 'endpoint' && node.wifi) {
    wifiRows.push(['Wi-Fi', wifiClientText(node.wifi, nameOf)]);
  }
  const { liveness } = useLiveness();
  const livenessOn = Boolean(liveness?.enabled);
  const nodeLiveness = livenessOn ? liveness?.nodes[node.node_id] : undefined;
  const isDevice = node.kind === 'device';
  const Icon = iconForRole(node.role);
  const score = nodeRiskScore(node);
  const level = riskLevel(score);
  const offline = isOffline(node.status, nodeLiveness);
  const cves = node.top_cves || [];
  // Absent in older graph files (and null when unscored): keep the old display.
  const summary = node.cve_summary || null;
  const cveTotal = summary ? summary.total : cves.length;
  // A device's CVEs come from NVD by software version: potential findings.
  const lookup = node.kind === 'device' ? node.cve_lookup : undefined;
  const deviceLookedUp = hasDeviceFindings(lookup);
  const reason = level === 'unscored' ? unscoredReason(node) : '';
  const ports = node.kind === 'device' && node.port_status ? Object.entries(node.port_status) : [];

  return (
    <EuiFlyout
      onClose={onClose}
      ownFocus={false}
      size="m"
      maxWidth={640}
      aria-labelledby="vmDetailTitle"
      data-test-subj="vmDetailFlyout"
    >
      <EuiFlyoutHeader hasBorder>
        <EuiFlexGroup alignItems="center" gutterSize="m" responsive={false}>
          <EuiFlexItem grow={false}>
            <span className="vmDetailIcon" style={{ borderColor: RISK_META[level].color }}>
              <Icon size={26} strokeWidth={1.5} />
            </span>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiTitle size="s">
              <h2 id="vmDetailTitle">{node.hostname || node.ip || node.node_id}</h2>
            </EuiTitle>
            <EuiText size="xs" color="subdued">
              {node.role || node.kind} · {node.discovery_method}{' '}
              {offline && <EuiBadge color="hollow">offline</EuiBadge>}
              {node.stale && <EuiBadge color="hollow">stale</EuiBadge>}
            </EuiText>
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="s" />
        <EuiBadge color={RISK_META[level].color} data-test-subj="vmDetailRisk">
          {level === 'unscored' ? 'Unscored' : `${RISK_META[level].label} · risk ${riskLabel(score)}`}
        </EuiBadge>
        {lookup && lookup.stale && (
          <EuiBadge color="warning" data-test-subj="vmCveStale">
            stale
          </EuiBadge>
        )}
        {reason && (
          <EuiText size="xs" color="subdued" data-test-subj="vmUnscoredReason">
            <p>{reason}</p>
          </EuiText>
        )}
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <Section title="Identity">
          <EuiDescriptionList
            type="column"
            compressed
            className="vmFields"
            listItems={fields([
              ['Hostname', node.hostname],
              ['IP', node.ip],
              ['MAC', node.mac],
              ['Vendor', node.vendor],
              ['Model', node.model],
              ['Firmware', node.firmware],
              ...(lookup && lookup.product
                ? ([['Software', lookup.product]] as Array<[string, ReactNode]>)
                : []),
              ['Serial', node.serial],
              ['Role', node.role],
              ['Discovery method', node.discovery_method],
              ['Status', node.status],
              ...wifiRows,
              ...(livenessOn
                ? ([['Liveness', <LivenessValue value={nodeLiveness} />]] as Array<[string, ReactNode]>)
                : []),
            ])}
          />
        </Section>
        <EuiSpacer size="m" />

        {summary && (
          <>
            <RiskSummary score={score} summary={summary} />
            <EuiSpacer size="m" />
          </>
        )}

        {(!isDevice || deviceLookedUp) && (
          <Section title="Vulnerabilities" count={cveTotal}>
            {lookup && (
              <>
                <EuiText size="xs" color="subdued" data-test-subj="vmCvePotential">
                  <p>{potentialText(lookup)}</p>
                  {lookup.stale && <p>{staleText(lookup)}</p>}
                </EuiText>
                <EuiSpacer size="s" />
              </>
            )}
            {cveTotal > cves.length && (
              <>
                <EuiText size="xs" color="subdued" data-test-subj="vmCveShowing">
                  <p>
                    Showing the {cves.length} worst of {cveTotal}.
                  </p>
                </EuiText>
                <EuiSpacer size="s" />
              </>
            )}
            {cves.length === 0 ? (
              <EuiText size="s" color="subdued">
                <p>
                  {isDevice
                    ? score === null
                      ? 'No CVEs found.'
                      : 'NVD lists no CVEs for this software version.'
                    : `No CVEs reported${score === null ? ' (host is unscored)' : ''}.`}
                </p>
              </EuiText>
            ) : (
              cves.map((c, i) => {
                const sev = severityLevel(c.severity, c.cvss);
                return (
                  <React.Fragment key={`${c.cve}:${i}`}>
                    {i > 0 && <EuiSpacer size="s" />}
                    <EuiPanel paddingSize="s" hasShadow={false} hasBorder>
                      <EuiFlexGroup justifyContent="spaceBetween" alignItems="center" responsive={false} gutterSize="s">
                        <EuiFlexItem grow={false}>
                          <EuiText size="s">
                            <strong className="vmMono">{c.cve}</strong>
                          </EuiText>
                        </EuiFlexItem>
                        <EuiFlexItem grow={false}>
                          <EuiBadge color={RISK_META[sev].color}>
                            {c.severity}
                            {c.cvss !== null && ` · ${c.cvss}`}
                            {c.cvss_version && ` (v${c.cvss_version})`}
                          </EuiBadge>
                        </EuiFlexItem>
                      </EuiFlexGroup>
                      {(c.package || c.version) && (
                        <EuiText size="xs" color="subdued">
                          <p>
                            {c.package}
                            {c.version && ` · ${c.version}`}
                          </p>
                        </EuiText>
                      )}
                      {c.description && (
                        <EuiText size="xs" className="vmCveDesc">
                          <p>{cleanDescription(c.description)}</p>
                        </EuiText>
                      )}
                    </EuiPanel>
                  </React.Fragment>
                );
              })
            )}
          </Section>
        )}

        {node.kind === 'device' && (
          <>
            {(!isDevice || deviceLookedUp) && <EuiSpacer size="m" />}
            <ConfigChecks node={node} meta={graph?.metadata} />
            <EuiSpacer size="m" />
            <Section title="Ports" count={ports.length}>
              {ports.length === 0 ? (
                <EuiText size="s" color="subdued">
                  <p>No port status reported.</p>
                </EuiText>
              ) : (
                <div className="vmPorts">
                  {ports.map(([name, state]) => (
                    <EuiHealth key={name} color={state === 'up' ? 'success' : 'danger'} title={state} textSize="xs">
                      <span className="vmMono">{name}</span>
                    </EuiHealth>
                  ))}
                </div>
              )}
              {node.port_status_note && (
                <EuiText size="xs" color="subdued">
                  <p>{node.port_status_note}</p>
                </EuiText>
              )}
            </Section>
            <EuiSpacer size="m" />
            <Section title="Topology ports">
              <EuiDescriptionList
                type="column"
                compressed
                className="vmFields"
                listItems={fields([
                  ['Neighbor ports', (node.neighbor_ports || []).join(', ')],
                  ['Uplink ports', (node.uplink_ports || []).join(', ')],
                ])}
              />
            </Section>
          </>
        )}
      </EuiFlyoutBody>
    </EuiFlyout>
  );
}
