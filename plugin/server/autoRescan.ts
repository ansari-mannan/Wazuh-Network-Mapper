import { ScanState } from '../common';

// Automatic rescan: when a liveness pass suggests one (a port came up with
// nothing linked to it, or an active Wazuh agent is not in the graph), start a
// scan the same way a manual scan starts. Never while a scan runs, and never
// sooner than minIntervalSeconds after the last scan started, whether that one
// was automatic or manual.

export interface AutoRescanOptions {
  /** vulnmapper.liveness.autoRescan */
  enabled: boolean;
  /** vulnmapper.liveness.minRescanIntervalSeconds */
  minIntervalSeconds: number;
  getScan: () => ScanState;
  /** the manual-scan path (startScan); false if a scan is already running */
  startScan: () => boolean;
  logger: { info: (message: string) => void };
  now?: () => number;
}

/** Returns the per-pass hook: give it the saved state document; true if it started a scan. */
export function createAutoRescan(opts: AutoRescanOptions): (doc: unknown) => boolean {
  const now = opts.now || Date.now;
  let lastAutoStart: number | null = null;

  return (doc: unknown) => {
    const d = (doc && typeof doc === 'object' ? doc : {}) as {
      rescan_suggested?: unknown;
      rescan_reasons?: unknown;
    };
    if (!opts.enabled || d.rescan_suggested !== true) return false;
    const scan = opts.getScan();
    if (scan.status === 'running') return false;

    const manualStart = scan.startedAt ? Date.parse(scan.startedAt) : NaN;
    const last = Math.max(lastAutoStart ?? -Infinity, Number.isNaN(manualStart) ? -Infinity : manualStart);
    const t = now();
    if (t - last < opts.minIntervalSeconds * 1000) return false;

    if (!opts.startScan()) return false;
    lastAutoStart = t;
    const reasons = Array.isArray(d.rescan_reasons) ? d.rescan_reasons.filter((r) => typeof r === 'string') : [];
    opts.logger.info(`automatic rescan started: ${reasons.join('; ') || 'suggested by the liveness pass'}`);
    return true;
  };
}
