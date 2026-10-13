// How the map shows one route ("Show on map" from Attack paths). The route's
// nodes get a numbered ring in travel order, with Start and Target tags, and
// its links an arrowhead pointing the way the route travels. Nothing else
// changes for a device: a switch, router or access point off the route is
// drawn as on the normal map. Only hosts off the route fade.

/** A node's place on the route: its step number (1 = start) and end tag. */
export interface RouteMark {
  step: number;
  end?: 'start' | 'target';
}

/**
 * Step numbers in travel order for the ordered route walk (start first, target
 * last). A node the route crosses twice keeps its first number.
 */
export function routeMarks(walk: string[]): Map<string, RouteMark> {
  const marks = new Map<string, RouteMark>();
  for (const id of walk) if (!marks.has(id)) marks.set(id, { step: marks.size + 1 });
  if (walk.length) {
    marks.get(walk[0])!.end = 'start';
    const last = marks.get(walk[walk.length - 1])!;
    if (walk.length > 1 && walk[walk.length - 1] !== walk[0]) last.end = 'target';
  }
  return marks;
}

/**
 * For each drawn link the route travels along, the end that carries the
 * arrowhead: 'end' when the route goes from the link's drawn source to its
 * drawn target, 'start' when it goes the other way. A link the route uses in
 * both directions keeps the first. Links off the route are not in the map.
 */
export function routeArrows(
  walk: string[],
  links: Array<{ id: string; source: string; target: string }>
): Map<string, 'start' | 'end'> {
  const travelled = new Map<string, string>(); // unordered pair -> node travelled to first
  for (let i = 0; i + 1 < walk.length; i++) {
    const key = [walk[i], walk[i + 1]].sort().join('\n');
    if (!travelled.has(key)) travelled.set(key, walk[i + 1]);
  }
  const arrows = new Map<string, 'start' | 'end'>();
  for (const l of links) {
    const to = travelled.get([l.source, l.target].sort().join('\n'));
    if (to !== undefined) arrows.set(l.id, to === l.target ? 'end' : 'start');
  }
  return arrows;
}

/**
 * The node's extra class in the spotlight: 'vmOnRoute' (the ring) for a node
 * on the route, 'vmDim' for a host off it, '' for everything else (devices
 * off the route, and every node when no route is shown).
 *
 * ``onRoute`` comes from the route walk; links from older bookmarks carry only
 * the highlight and pass-through sets, which then decide it.
 */
export function highlightClass(
  node: { id: string; kind: string },
  highlight: Set<string> | null,
  passThrough: Set<string>,
  marks: Map<string, RouteMark> | null = null
): string {
  if (!highlight) return '';
  const onRoute = marks ? marks.has(node.id) : highlight.has(node.id) || passThrough.has(node.id);
  if (onRoute) return 'vmOnRoute';
  return node.kind === 'device' ? '' : 'vmDim';
}
