import React, { useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useLocation } from 'react-router-dom';
import {
  EuiButton,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiListGroup,
  EuiListGroupItem,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiSwitch,
  EuiText,
  EuiTextColor,
  EuiTitle,
} from '@elastic/eui';
import { GraphNode, GraphResponse, LivenessResponse } from '../../../common';
import { useGraph } from '../../lib/graph';
import { useLiveness } from '../../lib/liveness';
import { useServices } from '../../lib/services';
import { livenessMethod } from '../../lib/livenessText';
import { TopologyView, TopologyViewHandle } from './TopologyView';
import { DeviceDetail, formatSeen } from './DeviceDetail';
import { hiddenKeyOf, inactiveHosts } from './inactive';

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

function InactivePanel({ hosts, liveness, onSelect }: {
  hosts: GraphNode[];
  liveness: LivenessResponse;
  onSelect: (nodeId: string) => void;
}) {
  return (
    <EuiPanel paddingSize="s" className="vmInactivePanel" data-test-subj="vmInactivePanel">
      <EuiTitle size="xxs">
        <h3>Inactive ({hosts.length})</h3>
      </EuiTitle>
      <EuiSpacer size="xs" />
      <EuiListGroup flush gutterSize="none" maxWidth={false}>
        {hosts.map((n) => {
          const l = liveness.nodes[n.node_id];
          return (
            <EuiListGroupItem
              key={n.node_id}
              size="xs"
              wrapText
              onClick={() => onSelect(n.node_id)}
              data-test-subj="vmInactiveHost"
              label={
                <span>
                  {n.hostname ? <strong>{n.hostname}</strong> : <span className="vmMono">{n.ip || '—'}</span>}
                  <br />
                  <EuiTextColor color="subdued">
                    <small>
                      <span className="vmMono">{n.mac || '—'}</span>
                      <br />
                      last seen {formatSeen(l?.last_seen)}
                      <br />
                      via {l ? livenessMethod(l) : 'not checked'}
                    </small>
                  </EuiTextColor>
                </span>
              }
            />
          );
        })}
      </EuiListGroup>
    </EuiPanel>
  );
}

export function TopologyPage() {
  const { graph, loading, error, reload } = useGraph();
  const { liveness } = useLiveness();
  const { history } = useServices();
  const location = useLocation();
  const highlightKey = new URLSearchParams(location.search).get('highlight') || '';
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [hideInactive, setHideInactive] = useState(true);
  const view = useRef<TopologyViewHandle>(null);
  const { ref, height } = useFillHeight();
  const selected = graph?.nodes.find((n) => n.node_id === selectedId) || null;

  const livenessOn = Boolean(liveness?.enabled);
  const hidden = useMemo(
    () => (graph && liveness && livenessOn && hideInactive ? inactiveHosts(graph, liveness) : []),
    [graph, liveness, livenessOn, hideInactive]
  );
  // The canvas re-lays out only when this key changes, not on every poll.
  const hiddenKey = hiddenKeyOf(hidden);

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
        {livenessOn && (
          <EuiFlexItem grow={false}>
            <EuiSwitch
              compressed
              label="Hide inactive hosts"
              checked={hideInactive}
              onChange={(e) => setHideInactive(e.target.checked)}
              data-test-subj="vmHideInactive"
            />
          </EuiFlexItem>
        )}
        {highlightKey && (
          <EuiFlexItem grow={false}>
            <EuiButton
              size="s"
              iconType="cross"
              onClick={() => history.push('/topology')}
              data-test-subj="vmClearHighlight"
            >
              Clear highlight
            </EuiButton>
          </EuiFlexItem>
        )}
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
        {graph && !livenessOn ? (
          <EuiPanel paddingSize="none" className="vmTopology" style={{ height: '100%' }}>
            <TopologyView ref={view} graph={graph} selectedId={selectedId} onSelect={setSelectedId} highlightKey={highlightKey} />
          </EuiPanel>
        ) : graph ? (
          // Liveness on: the canvas, plus the hidden hosts beside it.
          <EuiFlexGroup gutterSize="s" responsive={false} style={{ height: '100%' }}>
            <EuiFlexItem style={{ minWidth: 0 }}>
              <EuiPanel paddingSize="none" className="vmTopology" style={{ height: '100%' }}>
                <TopologyView
                  ref={view}
                  graph={graph}
                  selectedId={selectedId}
                  onSelect={setSelectedId}
                  hiddenKey={hiddenKey}
                  highlightKey={highlightKey}
                />
              </EuiPanel>
            </EuiFlexItem>
            {liveness && hidden.length > 0 && (
              <EuiFlexItem grow={false}>
                <InactivePanel hosts={hidden} liveness={liveness} onSelect={setSelectedId} />
              </EuiFlexItem>
            )}
          </EuiFlexGroup>
        ) : (
          loading && <EuiLoadingSpinner size="xl" />
        )}
      </div>
      {selected && <DeviceDetail node={selected} onClose={() => setSelectedId(null)} />}
    </>
  );
}
