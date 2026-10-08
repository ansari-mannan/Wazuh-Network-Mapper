import { WifiInfo } from '../../common';

// Wi-Fi lines for the detail flyout.

/** "BIG-CYFOR-5G on CYFOR-AP1 (Do1)" for a Wi-Fi client. */
export function wifiClientText(wifi: WifiInfo, nameOf: (nodeId: string) => string): string {
  const parts = [];
  if (wifi.ssid) parts.push(wifi.ssid);
  parts.push(`on ${nameOf(wifi.access_point)}`);
  if (wifi.radio) parts.push(`(${wifi.radio})`);
  return parts.join(' ');
}

/** "no clients", "1 client", "12 clients" for an access point. */
export function clientCountText(count: number): string {
  if (count === 0) return 'no clients';
  return count === 1 ? '1 client' : `${count} clients`;
}
