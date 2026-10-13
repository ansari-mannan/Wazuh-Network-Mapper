// The detail flyout for one node: identity, risk and CVE list (endpoints from
// Wazuh, devices from NVD), configuration checks and port grid for devices.
// The panels themselves are in DetailSections.tsx.
import React, { ReactNode } from 'react';
import {
  EuiBadge,
  EuiDescriptionList,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutHeader,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { GraphNode, NodeLiveness } from '../../../common';
import { useGraph } from '../../lib/graph';
import { useLiveness } from '../../lib/liveness';
import { clientCountText, wifiClientText } from '../../lib/wifiText';
import { hasDeviceFindings, unscoredReason } from '../../lib/deviceCveText';
import { deviceHintText, manufacturerText, nameSourceText, unmanagedText } from '../../lib/hostText';
import { NODE_LEVEL_META, nodeLevel } from '../../lib/risk';
import { findingsBadge } from '../../lib/findingsBadge';
import { ovssLine } from '../../lib/ovssText';
import { roleLabel } from '../../lib/roleLabel';
import { ConfigChecks } from './ConfigChecks';
import { DevicePorts, fields, LivenessValue, OpenPorts, RiskSummary, Section, Vulnerabilities } from './DetailSections';
import { iconForRole } from './icons';
import { isOffline } from './nodeStyle';
import { ProtectControl } from './ProtectControl';

type Rows = Array<[string, ReactNode]>;

// The identity rows, in display order; host-only and Wi-Fi rows only where they apply.
function identityRows(node: GraphNode, nameOf: (id: string) => string, liveness: Rows): Rows {
  const hostRows: Rows = [];
  if (node.kind === 'endpoint') {
    if (node.mac_type) hostRows.push(['Manufacturer', manufacturerText(node)]);
    if (node.name_source) hostRows.push(['Name from', nameSourceText(node.name_source)]);
    if (node.device_hint) hostRows.push(['Device type', deviceHintText(node.device_hint)]);
  }
  if (node.snmp) hostRows.push(['SNMP reports', node.sys_descr || 'its name only']);
  // An access point shows its client count; a Wi-Fi client its SSID and AP.
  const wifiRows: Rows = [];
  if (node.kind === 'device' && typeof node.wifi_clients === 'number') {
    wifiRows.push(['Wi-Fi clients', clientCountText(node.wifi_clients)]);
  }
  if (node.kind === 'endpoint' && node.wifi) {
    wifiRows.push(['Wi-Fi', wifiClientText(node.wifi, nameOf)]);
  }
  const lookup = node.cve_lookup;
  return [
    ['Hostname', node.hostname],
    ['IP', node.ip],
    ['MAC', node.mac],
    ...hostRows,
    ['Vendor', node.vendor],
    ['Model', node.model],
    ['Firmware', node.firmware],
    ...(lookup && lookup.product ? ([['Software', lookup.product]] as Rows) : []),
    ['Serial', node.serial],
    ['Role', node.role && roleLabel(node.role, node.kind)],
    ['Discovery method', node.discovery_method],
    ['Status', node.status],
    ...wifiRows,
    ...liveness,
  ];
}

export function DeviceDetail({ node, onClose }: { node: GraphNode; onClose: () => void }) {
  const { graph } = useGraph();
  const nameOf = (id: string) => {
    const other = graph?.nodes.find((n) => n.node_id === id);
    return (other && (other.hostname || other.ip)) || id;
  };
  const { liveness } = useLiveness();
  const livenessOn = Boolean(liveness?.enabled);
  const nodeLiveness: NodeLiveness | undefined = livenessOn ? liveness?.nodes[node.node_id] : undefined;
  const isDevice = node.kind === 'device';
  const Icon = iconForRole(node.role);
  // the map's colour: the OVSS tier, else the worst configuration finding
  const level = nodeLevel(node, findingsBadge(node)?.severity ?? null);
  const offline = isOffline(node, liveness);
  const cves = node.top_cves || [];
  // Absent in older graph files (and null when unscored): keep the old display.
  const summary = node.cve_summary || null;
  const cveTotal = summary ? summary.total : cves.length;
  // A device's CVEs come from NVD by software version: potential findings. So
  // do those of a host without an agent that answered SNMP.
  const lookup = node.cve_lookup;
  const unmanaged = unmanagedText(node);
  const showCves = !isDevice || hasDeviceFindings(lookup);
  const reason = node.node_tier ? '' : unscoredReason(node);
  const livenessRow: Rows = livenessOn ? [['Liveness', <LivenessValue value={nodeLiveness} />]] : [];

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
            <span className="vmDetailIcon" style={{ borderColor: NODE_LEVEL_META[level].color }}>
              <Icon size={26} strokeWidth={1.5} />
            </span>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiTitle size="s">
              <h2 id="vmDetailTitle">{node.hostname || node.ip || node.node_id}</h2>
            </EuiTitle>
            <EuiText size="xs" color="subdued">
              {node.role ? roleLabel(node.role, node.kind) : node.kind} · {node.discovery_method}{' '}
              {offline && <EuiBadge color="hollow">offline</EuiBadge>}
              {node.stale && <EuiBadge color="hollow">stale</EuiBadge>}
              {node.unmanaged && (
                <EuiBadge color="warning" data-test-subj="vmUnmanaged">
                  Unmanaged
                </EuiBadge>
              )}
            </EuiText>
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="s" />
        <EuiBadge
          color={node.node_tier ? NODE_LEVEL_META[node.node_tier].color : 'hollow'}
          data-test-subj="vmDetailRisk"
        >
          {ovssLine(node)}
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
        {unmanaged && (
          <EuiText size="xs" color="subdued" data-test-subj="vmUnmanagedText">
            <p>{unmanaged}</p>
          </EuiText>
        )}
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <ProtectControl nodeId={node.node_id} />
        <EuiSpacer size="m" />
        <Section title="Identity">
          <EuiDescriptionList
            type="column"
            compressed
            className="vmFields"
            listItems={fields(identityRows(node, nameOf, livenessRow))}
          />
        </Section>
        <EuiSpacer size="m" />

        {(summary || node.ovss_status) && (
          <>
            <RiskSummary node={node} summary={summary} />
            <EuiSpacer size="m" />
          </>
        )}

        {showCves && <Vulnerabilities node={node} cves={cves} total={cveTotal} unscored={!summary} lookup={lookup} />}

        {node.kind === 'endpoint' && node.open_ports && (
          <>
            {showCves && <EuiSpacer size="m" />}
            <OpenPorts node={node} />
          </>
        )}

        {node.kind === 'device' && (
          <>
            {showCves && <EuiSpacer size="m" />}
            <ConfigChecks node={node} meta={graph?.metadata} />
            <EuiSpacer size="m" />
            <DevicePorts node={node} />
          </>
        )}
      </EuiFlyoutBody>
    </EuiFlyout>
  );
}
