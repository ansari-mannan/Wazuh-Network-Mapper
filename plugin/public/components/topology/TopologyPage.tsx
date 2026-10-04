import React, { useLayoutEffect, useRef, useState } from 'react';
import {
  EuiButton,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingSpinner,
  EuiPanel,
  EuiText,
} from '@elastic/eui';
import { GraphResponse } from '../../../common';
import { useGraph } from '../../lib/graph';
import { TopologyView, TopologyViewHandle } from './TopologyView';
import { DeviceDetail } from './DeviceDetail';

// Counts line, all from the loaded graph. "Unparented" = endpoints the scanner
// could not attach to a switch port (parent_id null).
function counts(graph: GraphResponse) {
  const devices = graph.nodes.filter((n) => n.kind === 'device').length;
  const endpoints = graph.nodes.filter((n) => n.kind === 'endpoint');
  return [
    `${graph.nodes.length} nodes`,
    `${devices} devices`,
    `${endpoints.length} endpoints`,
    `${graph.edges.length} links`,
    `${endpoints.filter((n) => n.parent_id === null || n.parent_id === undefined).length} unparented`,
  ].join(' · ');
}

// Height of the canvas = whatever is left of the window below its top edge.
function useFillHeight() {
  const ref = useRef<HTMLDivElement>(null);
  const [height, setHeight] = useState(480);
  useLayoutEffect(() => {
    const update = () => {
      if (!ref.current) return;
      const top = ref.current.getBoundingClientRect().top + window.scrollY;
      setHeight(Math.max(360, window.innerHeight - top - 16));
    };
    update();
    window.addEventListener('resize', update);
    return () => window.removeEventListener('resize', update);
  }, []);
  return { ref, height };
}

export function TopologyPage() {
  const { graph, loading, error, reload } = useGraph();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const view = useRef<TopologyViewHandle>(null);
  const { ref, height } = useFillHeight();
  const selected = graph?.nodes.find((n) => n.node_id === selectedId) || null;

  return (
    <>
      <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false} wrap>
        <EuiFlexItem grow={false}>
          <EuiButton
            size="s"
            iconType="refresh"
            isLoading={loading}
            onClick={() => {
              setSelectedId(null);
              reload();
            }}
            data-test-subj="vmReloadGraph"
          >
            Reload graph
          </EuiButton>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButton
            size="s"
            iconType="editorUndo"
            isDisabled={!graph}
            onClick={() => view.current?.resetLayout()}
            data-test-subj="vmResetLayout"
          >
            Reset layout
          </EuiButton>
        </EuiFlexItem>
        <EuiFlexItem>
          {graph && (
            <EuiText size="s" color="subdued" data-test-subj="vmCounts">
              <p>{counts(graph)}</p>
            </EuiText>
          )}
        </EuiFlexItem>
      </EuiFlexGroup>
      <div style={{ height: 12 }} />
      {error && <EuiCallOut color="danger" iconType="alert" title={error} />}
      <div ref={ref} style={{ height }}>
        {graph ? (
          <EuiPanel paddingSize="none" className="vmTopology" style={{ height: '100%' }}>
            <TopologyView ref={view} graph={graph} selectedId={selectedId} onSelect={setSelectedId} />
          </EuiPanel>
        ) : (
          loading && <EuiLoadingSpinner size="xl" />
        )}
      </div>
      {selected && <DeviceDetail node={selected} onClose={() => setSelectedId(null)} />}
    </>
  );
}
