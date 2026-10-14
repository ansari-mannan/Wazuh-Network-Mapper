// Automatic rescan: when a liveness pass suggests one (a port came up with
// nothing linked to it, or an active agent is missing from the graph), start a
// scan as a manual one starts. Never while a scan runs, and never within
// minIntervalSeconds of the last scan's start, automatic or manual.
//
// It must not loop: a reason a completed automatic scan did not clear (an
// agent the scan does not collect, a client the graph has no node for) is
// settled, and only a new reason starts another scan; a reason that goes away
// and comes back is new again. After each failed automatic scan the interval
// doubles, up to MAX_BACKOFF_SECONDS; a completed one resets it.
import { ScanState } from '../common';

export const MAX_BACKOFF_SECONDS = 3600;

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
  // the reasons of the automatic scan started last, until its outcome is seen
  let pending: Set<string> | null = null;
  let settled = new Set<string>();
  let failures = 0;

  return (doc: unknown) => {
    const d = (doc && typeof doc === 'object' ? doc : {}) as {
      rescan_suggested?: unknown;
      rescan_reasons?: unknown;
    };
    if (!opts.enabled) return false;
    const scan = opts.getScan();
    if (scan.status === 'running') return false;
    const listed = Array.isArray(d.rescan_reasons) ? d.rescan_reasons.filter((r) => typeof r === 'string') : [];
    const reasons: string[] = d.rescan_suggested !== true ? [] : listed.length ? listed : ['suggested by the liveness pass'];

    if (pending) {
      // the automatic scan has ended; this is the first pass after it
      if (scan.status === 'failed') {
        failures += 1;
      } else {
        failures = 0;
        const unresolved = reasons.filter((r) => pending!.has(r));
        if (unresolved.length) {
          opts.logger.info(`automatic rescan completed but left unresolved (no rescan for these again): ${unresolved.join('; ')}`);
        }
        settled = new Set([...settled, ...unresolved]);
      }
      pending = null;
    }
    settled = new Set(reasons.filter((r) => settled.has(r))); // gone and back is new
    const fresh = reasons.filter((r) => !settled.has(r));
    if (!fresh.length) return false;

    const manualStart = scan.startedAt ? Date.parse(scan.startedAt) : NaN;
    const last = Math.max(lastAutoStart ?? -Infinity, Number.isNaN(manualStart) ? -Infinity : manualStart);
    const interval = Math.min(opts.minIntervalSeconds * 2 ** failures, Math.max(MAX_BACKOFF_SECONDS, opts.minIntervalSeconds));
    const t = now();
    if (t - last < interval * 1000) return false;

    if (!opts.startScan()) return false;
    lastAutoStart = t;
    pending = new Set(reasons);
    opts.logger.info(`automatic rescan started: ${fresh.join('; ')}`);
    return true;
  };
}
