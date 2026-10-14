// Wireless links on the map and on an access point's front panel: which
// links are Wi-Fi, the band a radio serves and how many clients each radio has.
import type { GraphEdge } from '../../common';

const RADIO = /^dot11radio/i;

/** A Wi-Fi client's link to its access point: confidence "wifi", or a host on a Dot11Radio port. */
export function isWireless(e: { type: string; confidence?: string; local_port?: string }): boolean {
  return e.confidence === 'wifi' || (e.type === 'endpoint_link' && RADIO.test(e.local_port || ''));
}

/** Dot11Radio0 is the 2.4 GHz radio and Dot11Radio1 the 5 GHz one; null for any other. */
export function bandOf(radio: string | null | undefined): string | null {
  if (/^dot11radio0$/i.test(radio || '')) return '2.4 GHz';
  if (/^dot11radio1$/i.test(radio || '')) return '5 GHz';
  return null;
}

/** "Wireless · OFFICE · 5 GHz (Dot11Radio1)"; the radio name alone when its band is unknown. */
export function wirelessText(ssid: string | null | undefined, radio: string | null | undefined): string {
  const band = bandOf(radio);
  const where = band ? `${band} (${radio})` : radio;
  return ['Wireless', ssid, where].filter(Boolean).join(' · ');
}

/** Clients per radio of one access point, from its wireless links. */
export function radioClients(apId: string, edges: GraphEdge[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const e of edges) {
    if (e.target === apId && e.local_port && isWireless(e)) out.set(e.local_port, (out.get(e.local_port) || 0) + 1);
  }
  return out;
}
