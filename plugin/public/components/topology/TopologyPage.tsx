import React, { useState } from 'react';
import { EuiCallOut, EuiLoadingSpinner, EuiPanel, EuiText } from '@elastic/eui';
import { useGraph } from '../../lib/graph';
import { TopologyView } from './TopologyView';

export function TopologyPage() {
  const { graph, loading, error } = useGraph();
  const [selected, setSelected] = useState<string | null>(null);

  if (error) return <EuiCallOut color="danger" iconType="alert" title={error} />;
  if (!graph) return loading ? <EuiLoadingSpinner size="xl" /> : null;
  return (
    <>
      <EuiText size="s" color="subdued" data-test-subj="vmCounts">
        <p>
          {graph.nodes.length} nodes · {graph.edges.length} links
          {selected ? ` · selected ${selected}` : ''}
        </p>
      </EuiText>
      <EuiPanel paddingSize="none" className="vmTopology vmTopology--page">
        <TopologyView graph={graph} onSelect={setSelected} />
      </EuiPanel>
    </>
  );
}
