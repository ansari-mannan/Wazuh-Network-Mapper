// The graph in use: when its file was written, how big it is, and what each
// stage of the scan behind it did (metadata.stages).
import React from 'react';
import { EuiBasicTable, EuiDescriptionList, EuiPanel, EuiSpacer, EuiText, EuiTextColor, EuiTitle } from '@elastic/eui';
import { ScanStageOutcome } from '../../../common';
import { useGraph } from '../../lib/graph';
import { formatTime } from './ScanStatus';

export function ScanStages({ stages, title = 'Last scan, stage by stage' }: { stages: ScanStageOutcome[]; title?: string }) {
  return (
    <>
      <EuiSpacer size="m" />
      <EuiTitle size="xxs">
        <h3>{title}</h3>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiBasicTable<ScanStageOutcome>
        compressed
        items={stages}
        data-test-subj="vmScanStages"
        columns={[
          { field: 'name', name: 'Stage' },
          {
            field: 'status',
            name: 'Result',
            width: '80px',
            render: (status: ScanStageOutcome['status']) =>
              status === 'failed' ? <EuiTextColor color="danger">Failed</EuiTextColor> : status === 'ran' ? 'Ran' : 'Skipped',
          },
          {
            field: 'seconds',
            name: 'Time',
            width: '70px',
            render: (s: number | null) => (s === null ? '—' : `${s} s`),
          },
          { field: 'note', name: 'Note', render: (note: string | null) => note || '' },
        ]}
      />
    </>
  );
}

export function GraphSource() {
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
      {graph?.metadata?.stages?.length ? <ScanStages stages={graph.metadata.stages} /> : null}
    </EuiPanel>
  );
}
