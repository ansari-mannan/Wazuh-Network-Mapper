import React, { useEffect, useMemo, useState } from 'react';
import {
  EuiBadge,
  EuiCallOut,
  EuiEmptyPrompt,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { AttackRoute, AttackStartingPoint, GraphResponse } from '../../../common';
import { useAttackPaths } from '../../lib/attackPathsData';
import { useGraph } from '../../lib/graph';
import { useServices } from '../../lib/services';
import {
  compareRoutes,
  IMPORTANCE_META,
  IMPORTANCE_RANK,
  likelihoodText,
  pageState,
  physicalPathNodeIds,
  routeNodeIds,
  routeWalk,
  targetState,
} from '../../lib/attackPaths';
import { RouteDetail } from './RouteDetail';

const keyOf = (r: AttackRoute) => `${r.target}|${r.start}`;

// A readable name for a node id, or for a spare-ports start (not a graph node).
function makeNameOf(graph: GraphResponse | null, starts: AttackStartingPoint[]) {
  const spare = new Map(starts.filter((s) => s.kind === 'spare_ports').map((s) => [s.id, s]));
  return (id: string) => {
    const node = graph?.nodes.find((n) => n.node_id === id);
    if (node) return node.hostname || node.ip || id;
    const sp = spare.get(id);
    if (sp) return `${sp.listed_ports ?? sp.ports?.length ?? 0} spare port(s) in VLAN ${sp.vlans[0]}`;
    return id;
  };
}

function RouteTile({
  route,
  nameOf,
  selected,
  onSelect,
}: {
  route: AttackRoute;
  nameOf: (id: string) => string;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <EuiPanel
      paddingSize="m"
      hasBorder
      onClick={onSelect}
      className={`vmRouteTile ${selected ? 'vmRouteTile--selected' : ''}`}
      data-test-subj="vmRouteTile"
    >
      <EuiFlexGroup gutterSize="s" alignItems="baseline" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiBadge color="hollow">#{route.rank}</EuiBadge>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiText size="s">
            <strong>{nameOf(route.target)}</strong>
          </EuiText>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiText size="xs" color="subdued">
        <p>from {nameOf(route.start)}</p>
      </EuiText>
      <EuiSpacer size="xs" />
      <EuiFlexGroup gutterSize="s" responsive={false} wrap alignItems="center">
        <EuiFlexItem grow={false}>
          <EuiText size="xs">{likelihoodText(route.likelihood)}</EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiBadge color="hollow">base score {route.highest_base_score}</EuiBadge>
        </EuiFlexItem>
      </EuiFlexGroup>
    </EuiPanel>
  );
}

export function AttackPathsPage() {
  const { doc, loading, error } = useAttackPaths();
  const { graph } = useGraph();
  const { history } = useServices();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const nameOf = useMemo(
    () => makeNameOf(graph, doc?.starting_points || []),
    [graph, doc]
  );

  // Dependants count per asset (correct in per_asset, blank on the target block).
  const dependants = useMemo(() => {
    const m = new Map<string, number>();
    for (const a of doc?.per_asset || []) m.set(a.id, a.dependants);
    return m;
  }, [doc]);

  // Target groups in importance order, routes within each sorted for the tiles.
  const groups = useMemo(() => {
    const targets = (doc?.targets || [])
      .slice()
      .sort((a, b) => IMPORTANCE_RANK[a.importance] - IMPORTANCE_RANK[b.importance]);
    return targets.map((t) => ({ target: t, routes: (t.routes || []).slice().sort(compareRoutes) }));
  }, [doc]);

  const allRoutes = useMemo(() => groups.flatMap((g) => g.routes), [groups]);
  const selected = allRoutes.find((r) => keyOf(r) === selectedKey) || null;

  // Select the top route once the data is in (and when the data changes).
  useEffect(() => {
    if (allRoutes.length && !allRoutes.some((r) => keyOf(r) === selectedKey)) {
      setSelectedKey(keyOf(allRoutes[0]));
    }
  }, [allRoutes, selectedKey]);

  if (loading && !doc) return <EuiLoadingSpinner size="xl" />;
  if (error) return <EuiCallOut color="danger" iconType="alert" title={error} />;

  const state = pageState(doc);
  if (state === 'absent') {
    return (
      <EuiPanel paddingSize="l">
        <EuiEmptyPrompt
          iconType="branch"
          title={<h2>No attack paths yet</h2>}
          body={<p>Run a scan to compute attack paths for the assets you have marked to protect.</p>}
          data-test-subj="vmNotComputed"
        />
      </EuiPanel>
    );
  }
  if (state === 'no_targets') {
    return (
      <EuiPanel paddingSize="l">
        <EuiEmptyPrompt
          iconType="bullseye"
          title={<h2>No assets marked to protect</h2>}
          body={
            <p>
              Marking an asset shows the routes that could reach it. Mark one from its panel on the
              Topology page.
            </p>
          }
          data-test-subj="vmNoTargets"
        />
      </EuiPanel>
    );
  }

  if (!doc) return null; // unreachable: pageState(null) is 'absent'

  // Light the physical path, not just the named assets: the taken-over assets
  // (start, target and each takeover step's destination) are the full highlight;
  // the switches/routers the hops really cross are pass-through (lighter).
  const onShowOnMap = (route: AttackRoute) => {
    const full = new Set<string>([route.start, route.target]);
    for (const s of route.steps) if (s.kind !== 'transit') full.add(s.to);
    const lit = new Set([...physicalPathNodeIds(routeWalk(route), graph?.edges || []), ...routeNodeIds(route)]);
    const pass = [...lit].filter((id) => !full.has(id));
    const q = new URLSearchParams({ highlight: [...full].join(','), pass: pass.join(',') });
    history.push(`/topology?${q.toString()}`);
  };

  return (
    <EuiFlexGroup className="vmAttackPaths" gutterSize="l" alignItems="flexStart">
      <EuiFlexItem grow={2} data-test-subj="vmRouteList">
        {groups.map(({ target, routes }) => {
          const meta = IMPORTANCE_META[target.importance];
          const tState = targetState(target);
          return (
            <React.Fragment key={target.id}>
              <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} wrap>
                <EuiFlexItem grow={false}>
                  <EuiTitle size="xs">
                    <h3>{target.label || nameOf(target.id)}</h3>
                  </EuiTitle>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiBadge color={meta.color}>{meta.label}</EuiBadge>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiText size="xs" color="subdued" data-test-subj="vmDependants">
                    {dependants.get(target.id) ?? 0} dependants
                  </EuiText>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiSpacer size="s" />
              {tState === 'missing' ? (
                <EuiText size="s" color="subdued">
                  <p>Not in the current graph{target.reason ? ` (${target.reason})` : ''}.</p>
                </EuiText>
              ) : tState === 'no_routes' ? (
                <EuiText size="s" color="subdued" data-test-subj="vmNoRoutes">
                  <p>No route found — nothing in the current graph reaches this asset.</p>
                </EuiText>
              ) : (
                routes.map((route) => (
                  <React.Fragment key={keyOf(route)}>
                    <RouteTile
                      route={route}
                      nameOf={nameOf}
                      selected={keyOf(route) === selectedKey}
                      onSelect={() => setSelectedKey(keyOf(route))}
                    />
                    <EuiSpacer size="s" />
                  </React.Fragment>
                ))
              )}
              <EuiSpacer size="l" />
            </React.Fragment>
          );
        })}
      </EuiFlexItem>
      <EuiFlexItem grow={3}>
        {selected ? (
          <RouteDetail
            route={selected}
            nameOf={nameOf}
            metadata={doc.metadata}
            onShowOnMap={() => onShowOnMap(selected)}
          />
        ) : (
          <EuiPanel paddingSize="l" hasBorder>
            <EuiText color="subdued">
              <p>Select a route to see how it reaches the asset.</p>
            </EuiText>
          </EuiPanel>
        )}
      </EuiFlexItem>
    </EuiFlexGroup>
  );
}
