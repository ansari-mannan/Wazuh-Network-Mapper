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
import { CveSummary, GraphNode } from '../../../common';
import { nodeRiskScore, RISK_META, riskLevel, RiskLevel } from '../../lib/risk';
import { iconForRole } from './icons';
import { isOffline, riskLabel } from './nodeStyle';

// Ported from frontend/risk-module/ui/topology/DeviceDetail.tsx to an OUI
// flyout: identity, risk, CVE list for endpoints, port grid for devices.

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

export function DeviceDetail({ node, onClose }: { node: GraphNode; onClose: () => void }) {
  const isDevice = node.kind === 'device';
  const Icon = iconForRole(node.role);
  const score = nodeRiskScore(node);
  const level = riskLevel(score);
  const offline = isOffline(node.status);
  const cves = node.kind === 'endpoint' ? node.top_cves || [] : [];
  // Absent in older graph files (and null when unscored): keep the old display.
  const summary = node.kind === 'endpoint' ? node.cve_summary || null : null;
  const cveTotal = summary ? summary.total : cves.length;
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
          {level === 'unscored'
            ? isDevice
              ? 'Unscored · no CVE data for devices yet'
              : 'Unscored'
            : `${RISK_META[level].label} · risk ${riskLabel(score)}`}
        </EuiBadge>
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
              ['Serial', node.serial],
              ['Role', node.role],
              ['Discovery method', node.discovery_method],
              ['Status', node.status],
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

        {!isDevice && (
          <Section title="Vulnerabilities" count={cveTotal}>
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
                <p>No CVEs reported{score === null ? ' (host is unscored)' : ''}.</p>
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
