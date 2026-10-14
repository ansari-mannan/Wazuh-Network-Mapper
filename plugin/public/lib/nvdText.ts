// Whether the NVD lookups used an API key, from the scanner's boolean
// (metadata.device_cves.api_key). The key itself never reaches the browser.

/** The scan-complete toast's line, or undefined when no device-CVE stage ran. */
export function nvdToastText(apiKey: boolean | null | undefined): string | undefined {
  if (apiKey === true) return 'NVD: key in use';
  if (apiKey === false) return 'NVD: no key (slower lookups)';
  return undefined;
}

/** Scan settings' "NVD API key" value for the latest graph. */
export function nvdKeyStatus(apiKey: boolean | null | undefined): string {
  if (apiKey === true) return 'in use';
  if (apiKey === false) return 'not set';
  return 'unknown (no device CVE lookup in this scan)';
}
