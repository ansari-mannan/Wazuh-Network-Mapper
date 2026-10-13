// How a node's role is shown to a person. graph.json and the API keep the raw
// codes ("l3-switch"); this is display only. A device's role always gets a
// proper name, a host's keeps its current wording. No theme imports: unit tested.

const DEVICE_ROLE_LABELS: Record<string, string> = {
  'l3-switch': 'Layer 3 switch',
  'l2-switch': 'Layer 2 switch',
  'access-point': 'Access point',
  router: 'Router / firewall',
};

/** "firewall" -> "Firewall", "wlan-ap" -> "Wlan ap": any other code made readable. */
function readable(code: string): string {
  const words = code.replace(/[-_]+/g, ' ').trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** The role as shown: a device's role by its proper name, a host's unchanged. */
export function roleLabel(role: string, kind: string = 'device'): string {
  if (kind !== 'device') return role;
  return DEVICE_ROLE_LABELS[role] ?? readable(role);
}
