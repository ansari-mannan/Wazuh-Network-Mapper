// A device's port list for the detail panel, marking the ports known only
// from the neighbour's side of the link (inferred_ports).
export function portsText(ports: string[] | undefined, inferred: string[] | undefined): string {
  const fromNeighbour = new Set(inferred || []);
  return (ports || []).map((p) => (fromNeighbour.has(p) ? `${p} (inferred from neighbour)` : p)).join(', ');
}
