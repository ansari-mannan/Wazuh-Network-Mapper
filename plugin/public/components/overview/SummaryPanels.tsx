// The overview's panels: risk, configuration findings and agent coverage,
// counted from the graph.
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
import { CONFIG_SEVERITIES, configFindingCounts, severityLabel } from '../../lib/checklistText';
import { coverageText } from '../../lib/hostText';
import { RISK_META } from '../../lib/risk';
import { tierTextColors } from '../../lib/theme';
import { configSeverityColor } from '../topology/ConfigChecks';
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

// Failed configuration checks by published severity; they do not change the
// risk levels counted beside them.
function ConfigPanel({ graph }: { graph: GraphResponse }) {
  const config = configFindingCounts(graph.nodes);
  const source = graph.metadata?.checklist?.source;
  return (
    <SummaryPanel title="Device configuration">
      {config.devices === 0 ? (
        <EuiText size="s" color="subdued" data-test-subj="vmConfigOverviewNone">
          <p>No configuration checks in the current graph; the next scan adds them.</p>
        </EuiText>
      ) : (
        <>
          <EuiFlexGrid columns={2} gutterSize="m" data-test-subj="vmConfigOverview">
            {CONFIG_SEVERITIES.map((k) => {
              const color = configSeverityColor(k === 'advisory' ? null : k);
              return (
                <EuiFlexItem key={k}>
                  <div className="vmRiskCount" style={{ borderColor: color === 'hollow' ? RISK_META.unscored.color : color }}>
                    <EuiStat
                      title={config.counts[k]}
                      description={severityLabel(k === 'advisory' ? null : k)}
                      titleSize="m"
                      titleColor={color === 'hollow' ? 'default' : color}
                      reverse
                    />
                  </div>
                </EuiFlexItem>
              );
            })}
          </EuiFlexGrid>
          <EuiSpacer size="s" />
          <EuiText size="xs" color="subdued" data-test-subj="vmConfigNote">
            <p>
              {plural(config.total, 'failed check')} on {config.withFindings} of{' '}
              {plural(config.devices, 'checked device')}
              {source && source !== 'scan' ? ` (from ${source})` : ''}. Advisory: no published severity.
            </p>
          </EuiText>
        </>
      )}
    </SummaryPanel>
  );
}

// How many hosts a Wazuh agent reports from. A host without one is a blind
// spot; it is information, not a finding, so it has no severity.
function CoveragePanel({ graph }: { graph: GraphResponse }) {
  const coverage = graph.metadata?.coverage;
  return (
    <SummaryPanel title="Agent coverage">
      {!coverage ? (
        <EuiText size="s" color="subdued" data-test-subj="vmCoverageNone">
          <p>This graph does not count hosts with and without an agent; the next scan adds it.</p>
        </EuiText>
      ) : (
        <>
          <EuiStat
            title={`${coverage.managed} of ${coverage.hosts}`}
            description={coverageText(coverage)}
            titleSize="m"
            reverse
            data-test-subj="vmCoverage"
          />
          <EuiSpacer size="s" />
          <EuiText size="xs" color="subdued" data-test-subj="vmCoverageNote">
            {coverage.unmanaged > 0 && (
              <p>
                {plural(coverage.unmanaged, 'unmanaged host')}: no agent reports their software, so their
                vulnerabilities are not known.
              </p>
            )}
            <p>
              Knowing every machine on the network is the first control of the CIS Controls v8.1 (Control 1, which
              asks to find unmanaged assets) and NIST SP 800-53 CM-8.
            </p>
          </EuiText>
        </>
      )}
    </SummaryPanel>
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
        <SummaryPanel title="Risk (OVSS tier)">
          <EuiFlexGrid columns={2} gutterSize="m">
            {risk.levels.map((l) => (
              <EuiFlexItem key={l.level}>
                <div className="vmRiskCount" style={{ borderColor: l.color }}>
                  <EuiStat
                    title={l.value}
                    description={l.label}
                    titleSize="m"
                    titleColor={tierTextColors[l.level]}
                    reverse
                  />
                </div>
              </EuiFlexItem>
            ))}
          </EuiFlexGrid>
          <EuiSpacer size="s" />
          <EuiText size="xs" color="subdued" data-test-subj="vmRiskNote">
            <p>
              Assets by the tier of their most urgent finding, of {plural(risk.total, 'asset')}.
              {risk.unassessed > 0 && ` ${risk.unassessed} Unassessed: nothing was found or looked up, which is not clean.`}
              {risk.unrated > 0 && ` ${risk.unrated} Unrated: no CVSS score for their CVEs.`}
              {risk.notScored > 0 && ` ${risk.notScored} not scored: this graph was written before OVSS.`}
            </p>
            <p>Device findings are potential: matched by software version.</p>
          </EuiText>
        </SummaryPanel>
      </EuiFlexItem>
      <EuiFlexItem>
        <ConfigPanel graph={graph} />
      </EuiFlexItem>
      <EuiFlexItem>
        <CoveragePanel graph={graph} />
      </EuiFlexItem>
    </EuiFlexGroup>
  );
}
