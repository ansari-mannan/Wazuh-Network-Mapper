// How a node looks in the route spotlight ("Show on map" from Attack paths).
// Network devices are never dimmed: a switch, router or access point on a
// route only carries traffic, and one off it is still part of the network the
// route crosses. Only hosts off the route fade.

/** The node's extra class: '' (as drawn normally), 'vmPassThrough' or 'vmDim'. */
export function highlightClass(
  node: { id: string; kind: string },
  highlight: Set<string> | null,
  passThrough: Set<string>
): string {
  if (!highlight || highlight.has(node.id) || node.kind === 'device') return '';
  return passThrough.has(node.id) ? 'vmPassThrough' : 'vmDim';
}
