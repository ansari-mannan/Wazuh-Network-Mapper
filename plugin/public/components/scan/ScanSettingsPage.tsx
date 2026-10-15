// The scan settings page: start a scan (with the optional active checks), set
// the scan schedule, browse the scan history and see where the current graph
// came from.
import React, { useState } from 'react';
import {
  EuiButton,
  EuiCallOut,
  EuiFieldPassword,
  EuiFlexGroup,
  EuiFlexItem,
  EuiForm,
  EuiFormRow,
  EuiPanel,
  EuiSpacer,
  EuiSwitch,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { ActiveChecks } from '../../../common';
import { useScan } from '../../lib/scan';
import { GraphSource } from './GraphSource';
import { ScanStatus } from './ScanStatus';
import { ScheduledScans } from './ScheduledScans';
import { ScanHistory } from './ScanHistory';

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
  {
    key: 'nmapUnmanaged',
    label: 'Service-scan unmanaged hosts with nmap',
    help: 'Actively connects to and probes the discovered unmanaged hosts (nmap -sV: open ports and service versions, then NVD for potential CVEs). Never managed hosts or network devices. nmap must be installed on the dashboard server.',
    testSubj: 'vmNmapUnmanaged',
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
  // a scan whose crawl polls no device keeps the previous map unless this is on
  const [replaceEmpty, setReplaceEmpty] = useState(false);
  // nmap every host again rather than reusing what it found in the last 24 h
  const [freshServiceScan, setFreshServiceScan] = useState(false);
  const seeds = scan?.seeds ?? [];

  const run = () => {
    if (!running) start(community, { ...checks, replaceEmpty, freshServiceScan });
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
            <EuiFormRow
              label="Crawl starts from"
              helpText="Set with vulnmapper.seeds in opensearch_dashboards.yml."
            >
              <EuiText size="s" data-test-subj="vmSeeds">
                {seeds.length
                  ? seeds.join(', ')
                  : "The dashboard server's default gateway and LLDP neighbours (no vulnmapper.seeds set)"}
              </EuiText>
            </EuiFormRow>
            <EuiFormRow helpText="Off: if no network device answers SNMP, the scan fails and the current map is kept.">
              <EuiSwitch
                label="Replace the map even if no device answered"
                checked={replaceEmpty}
                onChange={(e) => setReplaceEmpty(e.target.checked)}
                disabled={running}
                data-test-subj="vmReplaceEmpty"
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
            {checks.nmapUnmanaged && (
              <EuiFormRow helpText="Off: a host nmap answered for in the last 24 hours reuses that answer (nmap-cache.json beside the graph). On: every host is scanned again.">
                <EuiSwitch
                  label="Fresh service scan"
                  checked={freshServiceScan}
                  onChange={(e) => setFreshServiceScan(e.target.checked)}
                  disabled={running}
                  data-test-subj="vmFreshServiceScan"
                />
              </EuiFormRow>
            )}
            {checks.nmapUnmanaged && scan?.nmapAvailable === false && (
              <EuiCallOut
                size="s"
                color="warning"
                iconType="alert"
                title="nmap is not installed on the dashboard server"
                data-test-subj="vmNmapMissing"
              >
                <p>It is not on the server&apos;s PATH, so the service scan will be skipped. Install nmap there to use it.</p>
              </EuiCallOut>
            )}
            <EuiSpacer size="m" />
            <EuiButton fill iconType="play" onClick={run} isLoading={running} data-test-subj="vmRunScan">
              {running ? 'Scanning…' : 'Run scan'}
            </EuiButton>
          </EuiForm>
          <EuiSpacer size="m" />
          <ScanStatus scan={scan} />
        </EuiPanel>
        <EuiSpacer size="m" />
        <ScheduledScans />
        <EuiSpacer size="m" />
        <ScanHistory />
      </EuiFlexItem>
      <EuiFlexItem grow={2}>
        <GraphSource />
      </EuiFlexItem>
    </EuiFlexGroup>
  );
}
