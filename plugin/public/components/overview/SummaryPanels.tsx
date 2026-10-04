import React from 'react';
import {
  EuiFlexGrid,
  EuiFlexGroup,
  EuiFlexItem,
  EuiHealth,
  EuiPanel,
  EuiSpacer,
  EuiStat,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { GraphResponse } from '../../../common';
import { deviceStats, endpointStats, hostRiskStats, Slice } from '../../lib/stats';
import { Donut } from './Donut';

function SummaryPanel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <EuiPanel className="vmSummaryPanel" paddingSize="m">
      <EuiTitle size="xs">
        <h2>{title}</h2>
      </EuiTitle>
      <EuiSpacer size="m" />
      {children}
    </EuiPanel>
  );
}

function DonutWithLegend({ slices, caption }: { slices: Slice[]; caption: string }) {
  return (
    <EuiFlexGroup alignItems="center" gutterSize="l" responsive={false} wrap>
      <EuiFlexItem grow={false}>
        <Donut slices={slices} caption={caption} />
      </EuiFlexItem>
      <EuiFlexItem style={{ minWidth: 140 }}>
        {slices.length === 0 ? (
          <EuiText size="s" color="subdued">
            None in the current graph.
          </EuiText>
        ) : (
          slices.map((s) => (
            <div key={s.label} className="vmLegendRow">
              <EuiHealth color={s.color} textSize="s">
                <span>{s.label}</span>
              </EuiHealth>
              <EuiText size="s">
                <strong>{s.value}</strong>
              </EuiText>
            </div>
          ))
        )}
      </EuiFlexItem>
    </EuiFlexGroup>
  );
}

export function SummaryPanels({ graph }: { graph: GraphResponse }) {
  const devices = deviceStats(graph);
  const endpoints = endpointStats(graph);
  const risk = hostRiskStats(graph);

  return (
    <EuiFlexGroup gutterSize="m">
      <EuiFlexItem>
        <SummaryPanel title="Network devices">
          <DonutWithLegend slices={devices.slices} caption="devices" />
          <EuiSpacer size="s" />
          <EuiText size="s" color="subdued" data-test-subj="vmResponding">
            {devices.responding} of {devices.total} responding
          </EuiText>
        </SummaryPanel>
      </EuiFlexItem>
      <EuiFlexItem>
        <SummaryPanel title="Endpoints">
          <DonutWithLegend slices={endpoints.slices} caption="endpoints" />
        </SummaryPanel>
      </EuiFlexItem>
      <EuiFlexItem>
        <SummaryPanel title="Hosts by risk level">
          <EuiFlexGrid columns={2} gutterSize="m">
            {risk.levels.map((l) => (
              <EuiFlexItem key={l.level}>
                <div className="vmRiskCount" style={{ borderColor: l.color }}>
                  <EuiStat
                    title={l.value}
                    description={l.label}
                    titleSize="m"
                    titleColor={l.color}
                    reverse
                  />
                </div>
              </EuiFlexItem>
            ))}
          </EuiFlexGrid>
          <EuiSpacer size="s" />
          <EuiText size="xs" color="subdued">
            {risk.unscored > 0 && (
              <p>
                {risk.unscored} {risk.unscored === 1 ? 'host' : 'hosts'} unscored (no CVE data).
              </p>
            )}
            <p>Endpoints only; network devices have no CVE data yet.</p>
          </EuiText>
        </SummaryPanel>
      </EuiFlexItem>
    </EuiFlexGroup>
  );
}
