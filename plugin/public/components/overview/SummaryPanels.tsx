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
import { deviceStats, endpointStats, riskStats, Slice } from '../../lib/stats';
import { plural } from '../../lib/deviceCveText';
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
  const risk = riskStats(graph);

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
        <SummaryPanel title="Risk level">
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
          <EuiText size="xs" color="subdued" data-test-subj="vmRiskNote">
            <p>
              {plural(risk.endpoints.scored + risk.endpoints.unscored, 'endpoint')} and{' '}
              {plural(risk.devices.scored + risk.devices.unscored, 'network device')}.
              {risk.unscored > 0 &&
                ` ${risk.unscored} unscored (${plural(risk.endpoints.unscored, 'endpoint')}, ${plural(
                  risk.devices.unscored,
                  'device'
                )}): no CVE data.`}
            </p>
            {risk.devices.scored > 0 && <p>Device findings are potential: matched by software version.</p>}
          </EuiText>
        </SummaryPanel>
      </EuiFlexItem>
    </EuiFlexGroup>
  );
}
