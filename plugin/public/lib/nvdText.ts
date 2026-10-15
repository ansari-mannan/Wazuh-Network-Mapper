// Whether the NVD lookups used an API key, from the scanner's boolean
// (metadata.device_cves.api_key). The key itself never reaches the browser.

/** The scan-complete toast's line, or undefined when no device-CVE stage ran. */
export function nvdToastText(apiKey: boolean | null | undefined): string | undefined {
  if (apiKey === true) return 'NVD: key in use';
  if (apiKey === false) return 'NVD: no key (slower lookups)';
  return undefined;
}

// The key state the last scan-complete toast announced, remembered in this
// browser only. Storage can be missing or throw; then the line always shows.
const ANNOUNCED = 'vulnmapper.nvdKeyAnnounced';
type Store = Pick<Storage, 'getItem' | 'setItem'>;

function store(): Store | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

/**
 * The toast's NVD line for a completed scan, only when the key's state differs
 * from the one this browser last announced (or it announced none yet); the new
 * state is remembered. undefined otherwise, and when no device-CVE stage ran.
 */
export function nvdToastLine(apiKey: boolean | null | undefined, storage: Store | null = store()): string | undefined {
  if (typeof apiKey !== 'boolean') return undefined;
  let last: string | null = null;
  try {
    last = storage?.getItem(ANNOUNCED) ?? null;
  } catch {
    // unknown: announce it
  }
  if (last === String(apiKey)) return undefined;
  try {
    storage?.setItem(ANNOUNCED, String(apiKey));
  } catch {
    // not remembered: announced again next time
  }
  return nvdToastText(apiKey);
}

/** Scan settings' "NVD API key" value for the latest graph. */
export function nvdKeyStatus(apiKey: boolean | null | undefined): string {
  if (apiKey === true) return 'in use';
  if (apiKey === false) return 'not set';
  return 'unknown (no device CVE lookup in this scan)';
}
