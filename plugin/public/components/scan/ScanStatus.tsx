// What the scan in progress, or the last one, is doing: running, failed or done.
import React from 'react';
import { EuiCallOut, EuiFlexGroup, EuiFlexItem, EuiLoadingSpinner, EuiText } from '@elastic/eui';
import { ScanState } from '../../../common';
import { graphWarnings } from '../../lib/graphWarnings';

export const formatTime = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleString() : '—';

export function ScanStatus({ scan }: { scan: ScanState | null }) {
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
        <p data-test-subj="vmScanStage">
          <strong>{scan.stage ? `${scan.stage}…` : 'Starting…'}</strong>
        </p>
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
    const warnings = graphWarnings(scan.warnings, scan.snmp);
    return (
      <EuiCallOut
        color={warnings.length ? 'warning' : 'success'}
        iconType={warnings.length ? 'alert' : 'check'}
        title={warnings.length ? 'Scan completed with a warning' : 'Last scan completed'}
        data-test-subj="vmScanStatus-done"
      >
        {warnings.length > 0 && (
          <ul data-test-subj="vmScanStatusWarnings">
            {warnings.map((text) => (
              <li key={text}>{text}</li>
            ))}
          </ul>
        )}
        <p>
          {scan.message} Finished {formatTime(scan.finishedAt)}.
        </p>
        {scan.refining && (
          <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} data-test-subj="vmScanRefining">
            <EuiFlexItem grow={false}>
              <EuiLoadingSpinner size="s" />
            </EuiFlexItem>
            <EuiFlexItem>Scores refining… CVE records from cve.org are still arriving; the scores update by themselves.</EuiFlexItem>
          </EuiFlexGroup>
        )}
      </EuiCallOut>
    );
  }
  return (
    <EuiText size="s" color="subdued" data-test-subj="vmScanStatus-idle">
      <p>No scan has run since the dashboard server started.</p>
    </EuiText>
  );
}
