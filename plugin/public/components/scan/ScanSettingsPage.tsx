import React from 'react';
import { EuiEmptyPrompt, EuiPanel } from '@elastic/eui';

// Placeholder until the scan form and status are built (Phase 5).
export function ScanSettingsPage() {
  return (
    <EuiPanel paddingSize="l">
      <EuiEmptyPrompt
        iconType="gear"
        title={<h2>Scan settings</h2>}
        body={<p>The scan form and graph source details are built in the next step.</p>}
      />
    </EuiPanel>
  );
}
