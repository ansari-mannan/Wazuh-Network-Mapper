import React, { useState } from 'react';
import {
  EuiButton,
  EuiCallOut,
  EuiDescriptionList,
  EuiFieldPassword,
  EuiFlexGroup,
  EuiFlexItem,
  EuiForm,
  EuiFormRow,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiSwitch,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { ActiveChecks, ScanState } from '../../../common';
import { useGraph } from '../../lib/graph';
import { useScan } from '../../lib/scan';

const formatTime = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleString() : '—';

function ScanStatus({ scan }: { scan: ScanState | null }) {
  if (!scan) return null;
  if (scan.status === 'running') {
    return (
      <EuiCallOut
        color="primary"
        title={
          <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
            <EuiFlexItem grow={false}>
              <EuiLoadingSpinner size="m" />
            </EuiFlexItem>
            <EuiFlexItem>Scan running…</EuiFlexItem>
          </EuiFlexGroup>
        }
        data-test-subj="vmScanStatus-running"
      >
        <p>Started {formatTime(scan.startedAt)}. The current graph stays in use until it finishes.</p>
      </EuiCallOut>
    );
  }
  if (scan.status === 'failed') {
    return (
      <EuiCallOut color="danger" iconType="alert" title="Scan failed" data-test-subj="vmScanStatus-failed">
        <p>{scan.message}</p>
        <p>
          Finished {formatTime(scan.finishedAt)}. The previous graph was kept and is still shown.
        </p>
      </EuiCallOut>
    );
  }
  if (scan.finishedAt) {
    return (
      <EuiCallOut color="success" iconType="check" title="Last scan completed" data-test-subj="vmScanStatus-done">
        <p>
          {scan.message} Finished {formatTime(scan.finishedAt)}.
        </p>
      </EuiCallOut>
    );
  }
  return (
    <EuiText size="s" color="subdued" data-test-subj="vmScanStatus-idle">
      <p>No scan has run since the dashboard server started.</p>
    </EuiText>
  );
}

function GraphSource() {
  const { graph, fileTime } = useGraph();
  return (
    <EuiPanel paddingSize="m">
      <EuiTitle size="xs">
        <h2>Current graph</h2>
      </EuiTitle>
      <EuiSpacer size="m" />
      {graph ? (
        <EuiDescriptionList
          type="column"
          compressed
          data-test-subj="vmGraphSource"
          listItems={[
            { title: 'Graph file modified', description: formatTime(fileTime) },
            { title: 'Scan time (from the file)', description: formatTime(graph.metadata?.scan_time) },
            { title: 'Nodes', description: String(graph.nodes.length) },
            { title: 'Links', description: String(graph.edges.length) },
          ]}
        />
      ) : (
        <EuiText size="s" color="subdued">
          <p>No graph loaded.</p>
        </EuiText>
      )}
    </EuiPanel>
  );
}

// The optional active checks, in the order shown; what each sends, in one sentence.
const ACTIVE_CHECKS: Array<{ key: keyof ActiveChecks; label: string; help: string; testSubj: string }> = [
  {
    key: 'checkDefaultCommunities',
    label: 'Also test factory-default SNMP names (public, private)',
    help: 'Each device gets two extra read-only SNMP requests with these names; the network may log them as failed logins.',
    testSubj: 'vmCheckDefaultCommunities',
  },
  {
    key: 'checkManagementPorts',
    label: 'Test whether telnet and web management answer on devices that do not report it',
    help: 'Each such device gets one TCP connection to port 23 and one to port 80, closed at once; nothing is sent and no login is tried.',
    testSubj: 'vmCheckManagementPorts',
  },
  {
    key: 'probeUnmanagedSnmp',
    label: 'Ask unmanaged hosts for their identity over SNMP',
    help: 'Sends this scan’s SNMP credential to every host without a Wazuh agent (at most 256), and those machines are not verified: one that is hostile receives the credential.',
    testSubj: 'vmProbeUnmanagedSnmp',
  },
];

export function ScanSettingsPage() {
  const { scan, start } = useScan();
  // The community string lives only in this component's state: it is never
  // written to browser storage and is sent once, with the scan request.
  const [community, setCommunity] = useState('');
  // Each switch starts from the server's default (vulnmapper.<key>, off) until
  // the user flips it.
  const [choices, setChoices] = useState<Partial<ActiveChecks>>({});
  const checks = Object.fromEntries(
    ACTIVE_CHECKS.map(({ key }) => [key, choices[key] ?? Boolean(scan?.defaults?.[key])])
  ) as ActiveChecks;
  const running = scan?.status === 'running';

  const run = () => {
    if (!running) start(community, checks);
  };

  return (
    <EuiFlexGroup gutterSize="m" alignItems="flexStart">
      <EuiFlexItem grow={3}>
        <EuiPanel paddingSize="m">
          <EuiTitle size="xs">
            <h2>Run a scan</h2>
          </EuiTitle>
          <EuiSpacer size="m" />
          <EuiForm>
            <EuiFormRow
              label="SNMP community string"
              helpText="Sent to the server with this scan only and never stored in the browser. Leave empty to use the SNMP settings of the dashboard server's environment."
            >
              <EuiFieldPassword
                type="password"
                value={community}
                onChange={(e) => setCommunity(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') run();
                }}
                autoComplete="new-password"
                disabled={running}
                data-test-subj="vmCommunity"
              />
            </EuiFormRow>
            <EuiSpacer size="m" />
            <EuiTitle size="xxs">
              <h3>Active checks: optional, off by default</h3>
            </EuiTitle>
            <EuiText size="xs" color="subdued">
              <p>Each one sends something to the network that the scan otherwise would not.</p>
            </EuiText>
            <EuiSpacer size="s" />
            {ACTIVE_CHECKS.map(({ key, label, help, testSubj }) => (
              <EuiFormRow key={key} helpText={help}>
                <EuiSwitch
                  label={label}
                  checked={checks[key]}
                  onChange={(e) => setChoices({ ...choices, [key]: e.target.checked })}
                  disabled={running}
                  data-test-subj={testSubj}
                />
              </EuiFormRow>
            ))}
            <EuiSpacer size="m" />
            <EuiButton fill iconType="play" onClick={run} isLoading={running} data-test-subj="vmRunScan">
              {running ? 'Scanning…' : 'Run scan'}
            </EuiButton>
          </EuiForm>
          <EuiSpacer size="m" />
          <ScanStatus scan={scan} />
        </EuiPanel>
      </EuiFlexItem>
      <EuiFlexItem grow={2}>
        <GraphSource />
      </EuiFlexItem>
    </EuiFlexGroup>
  );
}
