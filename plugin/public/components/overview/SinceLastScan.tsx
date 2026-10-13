// The overview's "Since the last scan: +2 hosts, 15 new CVEs, 3 fixed", from
// the two newest scans in the history; nothing until there are two.
import React, { useMemo } from 'react';
import { EuiLink, EuiPanel, EuiSpacer, EuiText } from '@elastic/eui';
import { useHistoryChanges, useHistoryIndex } from '../../lib/history';
import { changesSummary, scanChanges } from '../../lib/scanChanges';
import { useServices } from '../../lib/services';

export function SinceLastScan() {
  const { history } = useServices();
  const { index } = useHistoryIndex();
  const latest = index && index.length > 1 ? index[0].id : null;
  const { data } = useHistoryChanges(latest);
  const summary = useMemo(
    () => (data?.previous ? changesSummary(scanChanges(data.previous, data.current)) : null),
    [data]
  );
  if (!latest || !summary) return null;
  return (
    <>
    <EuiPanel paddingSize="m" data-test-subj="vmSinceLastScan">
      <EuiText size="s">
        <p>
          <strong>Since the last scan:</strong> {summary}.{' '}
          <EuiLink onClick={() => history.push(`/scan?history=${encodeURIComponent(latest)}`)}>Scan history</EuiLink>
        </p>
      </EuiText>
    </EuiPanel>
    <EuiSpacer size="m" />
    </>
  );
}
