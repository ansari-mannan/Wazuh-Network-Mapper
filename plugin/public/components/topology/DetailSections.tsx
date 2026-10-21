// The panels of the detail flyout below its identity: risk, liveness, the CVE
// list, a host's open ports, and a device's ports.
import React, { ReactNode, useState } from 'react';
import {
  EuiBadge,
  EuiButtonEmpty,
  EuiDescriptionList,
  EuiFlexGroup,
  EuiFlexItem,
  EuiHealth,
  EuiNotificationBadge,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { CveLookup, CveSummary, CVE, DeviceNode, GraphEdge, GraphNode, NodeLiveness } from '../../../common';
import { formatSeen, livenessMethod } from '../../lib/livenessText';
import { osvText, potentialText, staleText } from '../../lib/deviceCveText';
import { conflictText, cvssSourceText, epssText, exposureText, ovssLine } from '../../lib/ovssText';
import { RISK_META, riskLevel, RiskLevel, TIER_META, TIERS } from '../../lib/risk';
import { portsText } from '../../lib/portText';
import { Faceplate } from '../device/Faceplate';
import { RouteEntry } from './highlight';

const EMPTY = '—';

export function Section({ title, count, children }: { title: string; count?: number; children: ReactNode }) {
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

/** Title/value rows for an EuiDescriptionList; a missing value shows as a dash. */
export function fields(pairs: Array<[string, ReactNode]>) {
  return pairs.map(([title, value]) => ({
    title,
    description: value === null || value === undefined || value === '' ? EMPTY : value,
  }));
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

/** The node's OVSS (score, tier, the inputs it was scored with) and its CVEs by CVSS band. */
export function RiskSummary({ node, summary }: { node: GraphNode; summary: CveSummary | null }) {
  const hist = node.ovss_hist;
  return (
    <Section title="Risk">
      <EuiDescriptionList
        type="column"
        compressed
        className="vmFields"
        data-test-subj="vmOvss"
        listItems={fields([
          ['OVSS', ovssLine(node)],
          ...((node.ovss_status
            ? [
                ['Exposure', exposureText(node.exposure, node.exposure_flag)],
                ['Dependency', node.dependency],
                ['Importance', node.importance ? node.importance : 'not marked'],
                ['KEV CVEs', node.kev_count],
              ]
            : []) as Array<[string, ReactNode]>),
          ['Worst CVE (CVSS)', node.max_cvss ?? summary?.max_cvss],
        ])}
      />
      {hist && (
        <>
          <EuiSpacer size="s" />
          <EuiFlexGroup gutterSize="xs" wrap responsive={false} data-test-subj="vmTierCounts">
            {TIERS.map((t) => (
              <EuiFlexItem grow={false} key={t}>
                <EuiBadge color={hist[t] > 0 ? TIER_META[t].color : 'hollow'}>
                  {t} {hist[t]}
                </EuiBadge>
              </EuiFlexItem>
            ))}
            <EuiFlexItem grow={false}>
              <EuiBadge color="hollow">Unrated {hist.Unrated}</EuiBadge>
            </EuiFlexItem>
          </EuiFlexGroup>
        </>
      )}
      {summary && (
        <>
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
        </>
      )}
    </Section>
  );
}

/** A CVE's OVSS tier, KEV, EPSS and CVSS source, and a mark when its scores conflict. */
export function CveOvss({ cve: c }: { cve: CVE }) {
  if (!c.tier) return null;
  return (
    <EuiFlexGroup gutterSize="xs" wrap responsive={false} alignItems="center" data-test-subj="vmCveOvss">
      <EuiFlexItem grow={false}>
        <EuiBadge color={c.tier === 'Unrated' ? 'hollow' : TIER_META[c.tier].color}>
          {c.tier}
          {typeof c.score === 'number' && ` · ${c.score}`}
        </EuiBadge>
      </EuiFlexItem>
      {c.kev && (
        <EuiFlexItem grow={false}>
          <EuiBadge color="danger" title="In CISA's Known Exploited Vulnerabilities catalogue">
            KEV
          </EuiBadge>
        </EuiFlexItem>
      )}
      <EuiFlexItem grow={false}>
        <EuiText size="xs" color="subdued">
          {[epssText(c.epss), cvssSourceText(c)].filter(Boolean).join(' · ')}
          {c.conflict === 1 && (
            <span className="vmConflict" title={conflictText(c)} aria-label={conflictText(c)}>
              {' '}≠
            </span>
          )}
        </EuiText>
      </EuiFlexItem>
    </EuiFlexGroup>
  );
}

const LIVENESS_HEALTH: Record<string, { color: string; label: string }> = {
  active: { color: 'success', label: 'Active' },
  inactive: { color: 'danger', label: 'Inactive' },
  unknown: { color: 'subdued', label: 'Unknown' },
};

export function LivenessValue({ value }: { value: NodeLiveness | undefined }) {
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

// The scanner keeps Windows line breaks as literal "\r\n" text in descriptions.
function cleanDescription(text: string): string {
  return text.replace(/\\r\\n|\\n|\\r/g, '\n').trim();
}

function severityLevel(severity: string | null, cvss: number | null): RiskLevel {
  const s = (severity || '').toLowerCase();
  if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') return s;
  return riskLevel(cvss);
}

function CveCard({ cve: c }: { cve: CVE }) {
  const sev = severityLevel(c.severity, c.cvss);
  return (
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
      <CveOvss cve={c} />
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
  );
}

interface VulnerabilitiesProps {
  node: GraphNode;
  cves: CVE[];
  total: number;
  unscored: boolean; // no CVE summary: the host or lookup could not be scored
  lookup: CveLookup | null | undefined;
}

export function Vulnerabilities({ node, cves, total, unscored, lookup }: VulnerabilitiesProps) {
  const isDevice = node.kind === 'device';
  const source = node.kind === 'endpoint' ? osvText(node) : '';
  return (
    <Section title="Vulnerabilities" count={total}>
      {source && (
        <>
          <EuiText size="xs" color="subdued" data-test-subj="vmCveSource">
            <p>{source}</p>
          </EuiText>
          <EuiSpacer size="s" />
        </>
      )}
      {lookup && (
        <>
          <EuiText size="xs" color="subdued" data-test-subj="vmCvePotential">
            <p>{potentialText(lookup)}</p>
            {lookup.stale && <p>{staleText(lookup)}</p>}
          </EuiText>
          <EuiSpacer size="s" />
        </>
      )}
      {total > cves.length && (
        <>
          <EuiText size="xs" color="subdued" data-test-subj="vmCveShowing">
            <p>
              Showing the {cves.length} worst of {total}.
            </p>
          </EuiText>
          <EuiSpacer size="s" />
        </>
      )}
      {cves.length === 0 ? (
        <EuiText size="s" color="subdued">
          <p>
            {isDevice
              ? unscored
                ? 'No CVEs found.'
                : 'NVD lists no CVEs for this software version.'
              : `No CVEs reported${unscored ? ' (host is unscored)' : ''}.`}
          </p>
        </EuiText>
      ) : (
        cves.map((c, i) => (
          <React.Fragment key={`${c.cve}:${i}`}>
            {i > 0 && <EuiSpacer size="s" />}
            <CveCard cve={c} />
          </React.Fragment>
        ))
      )}
    </Section>
  );
}

// The service scan's open ports (hosts without an agent); evidence on its own.
export function OpenPorts({ node }: { node: GraphNode }) {
  const openPorts = node.kind === 'endpoint' ? node.open_ports || [] : [];
  return (
    <Section title="Open ports" count={openPorts.length}>
      <EuiText size="xs" color="subdued">
        <p>From the service scan (nmap). The host has no Wazuh agent.</p>
      </EuiText>
      <EuiSpacer size="s" />
      {openPorts.length === 0 ? (
        <EuiText size="s" color="subdued">
          <p>It answered the scan, but no open port was found.</p>
        </EuiText>
      ) : (
        <EuiDescriptionList
          type="column"
          compressed
          className="vmFields"
          data-test-subj="vmOpenPorts"
          listItems={openPorts.map((p) => ({
            title: <span className="vmMono">{`${p.port}/${p.protocol}`}</span>,
            description: [p.service, p.product, p.version].filter(Boolean).join(' · ') || EMPTY,
          }))}
        />
      )}
    </Section>
  );
}

// The front panel by default; "Show as list" gives the plain port_status list.
export function DevicePorts({
  node,
  edges = [],
  route,
  entry,
  onSelectNode,
}: {
  node: DeviceNode;
  edges?: GraphEdge[];
  route?: string[];
  entry?: RouteEntry;
  onSelectNode?: (nodeId: string) => void;
}) {
  const [asList, setAsList] = useState(false);
  const ports = node.port_status ? Object.entries(node.port_status) : [];
  const hasPanel = ports.length > 0 || (node.ports || []).length > 0;
  return (
    <Section title="Ports" count={ports.length}>
      {hasPanel && (
        <EuiButtonEmpty
          size="xs"
          flush="left"
          iconType={asList ? 'inspect' : 'list'}
          onClick={() => setAsList(!asList)}
          data-test-subj="vmPortsToggle"
        >
          {asList ? 'Show front panel' : 'Show as list'}
        </EuiButtonEmpty>
      )}
      {hasPanel && !asList ? (
        <Faceplate node={node} edges={edges} route={route} entry={entry} onSelectNode={onSelectNode} />
      ) : ports.length === 0 ? (
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
  );
}

export function TopologyPorts({ node }: { node: DeviceNode }) {
  return (
    <Section title="Topology ports">
      <EuiDescriptionList
        type="column"
        compressed
        className="vmFields"
        listItems={fields([
          ['Neighbor ports', portsText(node.neighbor_ports, node.inferred_ports)],
          ['Uplink ports', portsText(node.uplink_ports, node.inferred_ports)],
        ])}
      />
    </Section>
  );
}
