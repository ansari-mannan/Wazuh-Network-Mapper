import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';
import { Logger } from '../../../src/core/server';
import { VulnmapperConfig } from './config';
import { createAutoRescan } from './autoRescan';
import { configuredChecks } from './config';
import { getLastChecks, getLastCommunity, getScan, startScan } from './scan';

// The background liveness check: every intervalSeconds, run
// `python -m vulnmapper.liveness` over the current graph and save its state
// document to liveness.json. It only reads graph.json (a scan is its sole
// writer) and only re-checks what the scan found. When a pass suggests a
// rescan (something new appeared), a scan is started the way a manual one is,
// within the limits in autoRescan.ts. Off unless vulnmapper.liveness.enabled
// is true.

let timer: NodeJS.Timeout | null = null;
let running = false;

/** liveness.json: the configured path, else beside graphPath. */
export function livenessPath(config: VulnmapperConfig): string | null {
  if (config.liveness.path) return config.liveness.path;
  if (!config.graphPath) return null;
  return path.join(path.dirname(path.resolve(config.graphPath)), 'liveness.json');
}

// The pass logs to stderr; its last non-empty line is the useful one on failure.
// The community is redacted in case it ever appears.
function lastLine(stderr: string, community?: string): string {
  const lines = stderr.split('\n').map((l) => l.trim()).filter(Boolean);
  let msg = lines.length ? lines[lines.length - 1] : '';
  if (community) msg = msg.split(community).join('***');
  return msg;
}

async function runPass(config: VulnmapperConfig, logger: Logger, onPass: (doc: unknown) => void) {
  const { backendDir, graphPath, pythonBin, liveness } = config;
  const outPath = livenessPath(config);
  // Skip the tick if a pass or a scan is running, or there is no graph yet.
  if (running || !backendDir || !graphPath || !outPath) return;
  if (getScan().status === 'running') return;
  try {
    await fs.access(graphPath);
  } catch {
    return;
  }

  running = true;
  // As in scan.ts: the community goes through the environment, never argv, and
  // is never logged. Without one, the SNMP_* variables already set are used.
  const env = { ...process.env };
  const community = getLastCommunity();
  if (community) env.SNMP_COMMUNITIES = community;

  // The Wazuh password for the agent method comes from the server's own
  // environment (WAZUH_PASS), like a scan's; it is never placed in argv.
  const args = ['-m', 'vulnmapper.liveness', '--graph', graphPath, '--state', outPath,
    '--threshold', String(liveness.missThreshold),
    '--agent-max-age', String(Math.round(liveness.agentMaxAgeSeconds))];
  const child = spawn(pythonBin, args, { cwd: backendDir, env });
  const chunks: Buffer[] = [];
  let stderr = '';
  child.stdout.on('data', (d: Buffer) => chunks.push(d));
  child.stderr.on('data', (d: Buffer) => {
    stderr = (stderr + d.toString()).slice(-4096); // keep the tail only
  });

  // A pass must not outlive its interval.
  const killer = setTimeout(() => child.kill(), liveness.intervalSeconds * 1000);
  const done = (message?: string) => {
    clearTimeout(killer);
    running = false;
    if (message) logger.warn(`liveness pass failed: ${message}`);
  };

  child.on('error', (e: Error) => done(`could not start ${pythonBin}: ${e.message}`));
  child.on('close', async (code: number | null, signal: string | null) => {
    if (!running) return; // 'error' already reported
    if (code !== 0) {
      done(signal ? `killed (${signal}) after ${liveness.intervalSeconds}s`
        : lastLine(stderr, community) || `exited with code ${code}`);
      return;
    }
    const out = Buffer.concat(chunks);
    let doc: unknown;
    try {
      doc = JSON.parse(out.toString()); // validate before replacing the good file
      const tmp = `${outPath}.tmp-${process.pid}`;
      await fs.writeFile(tmp, out);
      await fs.rename(tmp, outPath);
      done();
      logger.debug(`liveness pass saved to ${outPath}`);
    } catch (e) {
      done(`could not save liveness state: ${(e as Error).message}`);
      return;
    }
    onPass(doc);
  });
}

/** Start the timer (from the plugin's start()); a no-op unless enabled. */
export function startLiveness(config: VulnmapperConfig, logger: Logger) {
  if (timer || !config.liveness.enabled) return;
  if (!config.backendDir || !config.graphPath) {
    logger.warn('liveness is enabled but backendDir/graphPath are not set; not starting');
    return;
  }
  const { backendDir, graphPath, pythonBin, liveness } = config;
  logger.info(
    `liveness check every ${liveness.intervalSeconds}s` +
      (liveness.autoRescan ? `; automatic rescan at most every ${liveness.minRescanIntervalSeconds}s` : '')
  );
  const onPass = createAutoRescan({
    enabled: liveness.autoRescan,
    minIntervalSeconds: liveness.minRescanIntervalSeconds,
    getScan,
    // The manual-scan path, with the last community given to a scan (if any).
    startScan: () =>
      startScan({ pythonBin, backendDir, graphPath, community: getLastCommunity(),
        deviceCves: config.deviceCves,
        checks: getLastChecks() ?? configuredChecks(config),
        logger }),
    logger,
  });
  const tick = () => {
    runPass(config, logger, onPass).catch((e) => logger.warn(`liveness pass failed: ${e.message}`));
  };
  timer = setInterval(tick, config.liveness.intervalSeconds * 1000);
  tick(); // first pass now rather than one interval after start-up
}

/** Stop the timer (from the plugin's stop()). */
export function stopLiveness() {
  if (timer) clearInterval(timer);
  timer = null;
}
