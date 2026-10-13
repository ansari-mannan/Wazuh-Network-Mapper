// Attack paths that follow liveness: a scan writes attack_paths.json without
// it (its liveness.json describes the previous graph), so after each liveness
// pass the routes are recomputed with --liveness when the set of hosts it
// marks inactive has changed, or on the first pass made for a new graph.
// Through runExclusive, so never during a scan; a refused pass is retried by
// the next one.

export interface LivenessRecomputeOptions {
  /** vulnmapper.liveness.enabled */
  enabled: boolean;
  /** scan.ts runExclusive: null when a scan (or another task) is running */
  runExclusive: (task: () => Promise<void>) => Promise<void> | null;
  /** recomputeAttackPaths with --liveness */
  recompute: () => Promise<void>;
  logger: { info: (m: string) => void; warn: (m: string) => void };
}

/** The node_ids of hosts (not devices) a pass marks inactive, sorted. */
export function inactiveHosts(doc: unknown): string[] {
  const nodes = (doc as { nodes?: unknown })?.nodes;
  if (!nodes || typeof nodes !== 'object') return [];
  return Object.entries(nodes as Record<string, { state?: unknown }>)
    .filter(([id, rec]) => !id.startsWith('device:') && rec?.state === 'inactive')
    .map(([id]) => id)
    .sort();
}

/** Returns the per-pass hook: give it the saved state document; true if it started a recompute. */
export function createLivenessRecompute(opts: LivenessRecomputeOptions): (doc: unknown) => boolean {
  // what the last started recompute was for; undefined until the first
  let done: { scanTime: unknown; inactive: string } | undefined;

  return (doc: unknown) => {
    if (!opts.enabled) return false;
    const scanTime = (doc as { graph_scan_time?: unknown })?.graph_scan_time;
    const inactive = inactiveHosts(doc).join('\n');
    if (done && done.scanTime === scanTime && done.inactive === inactive) return false;
    const run = opts.runExclusive(opts.recompute);
    if (!run) {
      opts.logger.info('attack paths not recomputed for liveness: a scan is running; the next pass will try again');
      return false;
    }
    done = { scanTime, inactive };
    run.then(
      () => opts.logger.info('attack paths recomputed with the liveness state'),
      (e) => opts.logger.warn(`attack-path recompute with liveness failed: ${(e as Error).message}`)
    );
    return true;
  };
}
