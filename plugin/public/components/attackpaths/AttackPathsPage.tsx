// The attack paths page: for each protected asset, the most likely routes to
// it from attack_paths.json, ranked, with the detail of the one selected.
import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiCallOut,
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
  isStale,
  likelihoodText,
  pageState,
  physicalPathNodeIds,
  physicalPathWalk,
  routeNodeIds,
  routeWalk,
  spareStartText,
  targetState,
} from '../../lib/attackPaths';
import { RouteDetail } from './RouteDetail';
import { tierReason } from '../../lib/ovssText';
import { ProtectedAssets } from './ProtectedAssets';
import { graphColors } from '../../lib/theme';

const keyOf = (r: AttackRoute) => `${r.target}|${r.start}`;

// A readable name for a node id, or for a spare-ports start (not a graph node).
function makeNameOf(graph: GraphResponse | null, starts: AttackStartingPoint[]) {
  const spare = new Map(starts.filter((s) => s.kind === 'spare_ports').map((s) => [s.id, s]));
  const nameOf = (id: string): string => {
    const node = graph?.nodes.find((n) => n.node_id === id);
    if (node) return node.hostname || node.ip || id;
    const sp = spare.get(id);
    return sp ? spareStartText(sp, nameOf) : id;
  };
  return nameOf;
}

function RouteTile({
  route,
  nameOf,
  startName,
  selected,
  onSelect,
}: {
  route: AttackRoute;
  nameOf: (id: string) => string;
  startName: string;
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
      role="option"
      aria-selected={selected}
      aria-current={selected || undefined}
      tabIndex={selected ? 0 : -1}
    >
      <EuiFlexGroup gutterSize="s" alignItems="baseline" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiBadge color="hollow">#{route.rank}</EuiBadge>
        </EuiFlexItem>
        {selected && (
          <EuiFlexItem grow={false}>
            <EuiBadge color={graphColors.route}>Selected</EuiBadge>
          </EuiFlexItem>
        )}
        <EuiFlexItem>
          <EuiText size="s">
            <strong>{nameOf(route.target)}</strong>
          </EuiText>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiText size="xs" color="subdued">
        <p>from {startName}</p>
      </EuiText>
      <EuiSpacer size="xs" />
      <EuiFlexGroup gutterSize="s" responsive={false} wrap alignItems="center">
        <EuiFlexItem grow={false}>
          <EuiText size="xs">Likelihood: {likelihoodText(route.likelihood)}</EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiBadge color="hollow">Highest asset OVSS: {route.highest_ovss} / 10</EuiBadge>
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
  const listRef = useRef<HTMLDivElement>(null);

  const nameOf = useMemo(
    () => makeNameOf(graph, doc?.starting_points || []),
    [graph, doc]
  );
  // A route's start in words; spare ports also say when they sit on the target.
  const startName = (route: AttackRoute) => {
    const sp = doc?.starting_points.find((p) => p.id === route.start && p.kind === 'spare_ports');
    return sp ? spareStartText(sp, nameOf, route.target) : nameOf(route.start);
  };
  const reasonOf = useMemo(() => (id: string) => {
    const node = graph?.nodes.find((n) => n.node_id === id);
    return node ? tierReason(node.node_tier, node.top_cves) : null;
  }, [graph]);

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

  // Keep the selected card in view, and keep focus on it while the list has focus.
  useEffect(() => {
    const card = listRef.current?.querySelector<HTMLElement>('[aria-selected="true"]');
    if (!card) return;
    card.scrollIntoView?.({ block: 'nearest' });
    if (listRef.current?.contains(document.activeElement)) card.focus();
  }, [selectedKey]);

  // Up/down arrows move the selection through the ranked list.
  const onListKey = (e: React.KeyboardEvent) => {
    const step = e.key === 'ArrowDown' ? 1 : e.key === 'ArrowUp' ? -1 : 0;
    if (!step || !allRoutes.length) return;
    e.preventDefault();
    const i = allRoutes.findIndex((r) => keyOf(r) === selectedKey);
    setSelectedKey(keyOf(allRoutes[Math.min(allRoutes.length - 1, Math.max(0, i + step))]));
  };

  if (loading && !doc) return <EuiLoadingSpinner size="xl" />;
  if (error) return <EuiCallOut color="danger" iconType="alert" title={error} />;

  const state = pageState(doc);
  // The card is always there, so a first target can be marked before any routes exist.
  const notice =
    state === 'absent' ? (
      <EuiCallOut iconType="branch" title="No attack paths yet" data-test-subj="vmNotComputed">
        <p>Run a scan to compute attack paths for the assets you have marked to protect.</p>
      </EuiCallOut>
    ) : isStale(doc, graph?.metadata.scan_time) ? (
      <EuiCallOut color="warning" iconType="clock" title="These attack paths are out of date" data-test-subj="vmStale">
        <p>They were computed from an older scan than the map shows. A rescan will refresh them.</p>
      </EuiCallOut>
    ) : null;
  const header = (
    <>
      {notice && (
        <>
          {notice}
          <EuiSpacer size="m" />
        </>
      )}
      <ProtectedAssets />
    </>
  );
  if (state !== 'ok' || !doc) return header;
  const offlineStarts = doc.offline_starts || [];

  // Show the physical path, not just the named assets: the taken-over assets
  // (start, target and each takeover step's destination), the switches and
  // routers the hops really cross, and all of them in travel order.
  const onShowOnMap = (route: AttackRoute) => {
    const full = new Set<string>([route.start, route.target]);
    for (const s of route.steps) if (s.kind !== 'transit') full.add(s.to);
    // A spare-ports start is not a graph node: the route leaves from its switch,
    // and the map marks the ports it enters by (`entry`, `vlan`, `ports`).
    const spare = doc.starting_points.find((p) => p.id === route.start && p.kind === 'spare_ports');
    const walk = routeWalk(route);
    if (spare?.switch) walk[0] = spare.switch;
    const physical = physicalPathNodeIds(walk, graph?.edges || [], graph?.nodes || []);
    const lit = new Set([...physical, ...routeNodeIds(route)]);
    const pass = [...lit].filter((id) => !full.has(id));
    // the same path in travel order: the map numbers it and points its arrows
    const ordered = physicalPathWalk(walk, graph?.edges || [], graph?.nodes || []);
    const q = new URLSearchParams({ highlight: [...full].join(','), pass: pass.join(','), route: ordered.join(',') });
    if (spare?.switch) {
      q.set('entry', spare.switch);
      q.set('vlan', String(spare.vlans[0]));
      q.set('ports', (spare.ports || []).join(','));
    }
    history.push(`/topology?${q.toString()}`);
  };

  return (
    <>
    {header}
    {offlineStarts.length > 0 && (
      <>
        <EuiSpacer size="s" />
        <EuiText size="xs" color="subdued" data-test-subj="vmOfflineStarts">
          <p>
            Not used as starting points ({offlineStarts.length} offline):{' '}
            {offlineStarts.map((s) => `${nameOf(s.id)} (${s.detail})`).join(', ')}
          </p>
        </EuiText>
      </>
    )}
    <EuiSpacer size="l" />
    <EuiFlexGroup className="vmAttackPaths" gutterSize="l" alignItems="flexStart">
      <EuiFlexItem
        grow={2}
        data-test-subj="vmRouteList"
        onKeyDown={onListKey}
        style={{ '--vm-route': graphColors.route, '--vm-route-tint': `${graphColors.route}14` } as React.CSSProperties}
      >
        <div ref={listRef}>
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
                <div role="listbox" aria-label={`Routes to ${target.label || nameOf(target.id)}`}>
                {routes.map((route) => (
                  <React.Fragment key={keyOf(route)}>
                    <RouteTile
                      route={route}
                      nameOf={nameOf}
                      startName={startName(route)}
                      selected={keyOf(route) === selectedKey}
                      onSelect={() => setSelectedKey(keyOf(route))}
                    />
                    <EuiSpacer size="s" />
                  </React.Fragment>
                ))}
                </div>
              )}
              <EuiSpacer size="l" />
            </React.Fragment>
          );
        })}
        </div>
      </EuiFlexItem>
      <EuiFlexItem grow={3}>
        {selected ? (
          <RouteDetail
            route={selected}
            nameOf={nameOf}
            startName={startName(selected)}
            spare={doc.starting_points.find((p) => p.id === selected.start && p.kind === 'spare_ports')}
            reasonOf={reasonOf}
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
    </>
  );
}
