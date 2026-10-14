// Running a scan: spawns `python -m vulnmapper` with the configured options,
// follows its stage lines on stderr, and swaps in the new files only on success.
import { spawn } from 'child_process';
import { accessSync, constants, promises as fs } from 'fs';
import path from 'path';
import { Logger } from '../../../src/core/server';
import { ActiveChecks, ScanState, ScanTrigger } from '../common';
import { attackPathsFilePath, targetsFilePath, vulnerabilitiesFilePath } from './targets';
import { archiveScan } from './history';

// One module-level state object: the server process runs one scan at a time.
let scan: ScanState = { status: 'idle', message: null, startedAt: null, finishedAt: null };
// The last community a scan was started with, for the liveness pass's SNMP
// probes. Memory only: never logged, written to disk or placed in argv.
let lastCommunity: string | undefined;
// The last scan's choice of active checks, so an automatic rescan does not
// silently change them.
let lastChecks: Partial<ActiveChecks> | undefined;

export function getScan(): ScanState {
  return scan;
}

// A file-only task that must not overlap a scan or another such task: the
// liveness pass's attack-path recompute and a protected-asset rescore, which
// write the same files. It holds the same lock: no scan starts while it runs.
let exclusiveTask = false;

/** Run task unless a scan or another such task is running; null if refused. */
export function runExclusive(task: () => Promise<void>): Promise<void> | null {
  if (scan.status === 'running' || exclusiveTask) return null;
  exclusiveTask = true;
  return task().finally(() => {
    exclusiveTask = false;
  });
}

export function getLastCommunity(): string | undefined {
  return lastCommunity;
}

export function getLastChecks(): Partial<ActiveChecks> | undefined {
  return lastChecks;
}

// Each active check's scanner flag.
const CHECK_FLAGS: Record<keyof ActiveChecks, string> = {
  checkDefaultCommunities: '--check-default-communities',
  checkManagementPorts: '--check-management-ports',
  probeUnmanagedSnmp: '--probe-unmanaged-snmp',
  nmapUnmanaged: '--nmap-unmanaged',
};

interface ScanOptions {
  pythonBin: string;
  backendDir: string;
  graphPath: string;
  community?: string;
  // false: the scanner skips the device CVE stage (--no-device-cves)
  deviceCves?: boolean;
  // vulnmapper.scanTimeoutSeconds: a scan running longer is killed and fails
  timeoutSeconds?: number;
  // vulnmapper.seeds: the IPs the crawl starts from
  seeds?: string[];
  // swap the new map in even when its crawl polled no device
  replaceEmpty?: boolean;
  // the optional active checks that are on (see CHECK_FLAGS)
  checks?: Partial<ActiveChecks>;
  trigger?: ScanTrigger;
  /** called once the scan ends: ok false for a failed scan */
  onDone?: (ok: boolean, message: string) => void;
  logger: Logger;
}

// The scanner logs to stderr and ends a failed run with one plain message line
// (e.g. "vulnmapper: WAZUH_PASS is not set; ..."), so the last non-empty line is
// the useful one to show. The community string is redacted in case it appears.
export function failureMessage(stderr: string, code: number | null, community?: string): string {
  const lines = stderr.split('\n').map((l) => l.trim()).filter(Boolean);
  let msg = lines.length ? lines[lines.length - 1] : `scanner exited with code ${code}`;
  if (community) msg = msg.split(community).join('***');
  return msg;
}

// The scanner announces each stage on stderr as "... vulnmapper.pipeline: stage: <label>".
const STAGE_LINE = /vulnmapper\.pipeline: stage: (.+)$/;

/** The last stage announced in these complete stderr lines, or null. */
export function latestStage(lines: string): string | null {
  let stage: string | null = null;
  for (const line of lines.split('\n')) {
    const m = STAGE_LINE.exec(line.trim());
    if (m) stage = m[1];
  }
  return stage;
}

/** Whether an executable `bin` is on this PATH (the scanner inherits the server's). */
export function onPath(bin: string, pathEnv = process.env.PATH || ''): boolean {
  return pathEnv.split(path.delimiter).some((dir) => {
    if (!dir) return false;
    try {
      accessSync(path.join(dir, bin), constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
}

/** The scanner's arguments. Never a credential: those go through the environment. */
export function scanArgs(
  out: { vulns: string; paths: string; targets: string },
  {
    deviceCves = true,
    checks = {},
    seeds = [],
  }: { deviceCves?: boolean; checks?: Partial<ActiveChecks>; seeds?: string[] }
): string[] {
  const args = ['-m', 'vulnmapper', '--vulns-out', out.vulns, '--paths-out', out.paths, '--targets', out.targets];
  // addresses are not secrets; the = form keeps a value from reading as a flag
  for (const ip of seeds) args.push(`--seed=${ip}`);
  if (!deviceCves) args.push('--no-device-cves');
  for (const key of Object.keys(CHECK_FLAGS) as Array<keyof ActiveChecks>) {
    if (checks[key]) args.push(CHECK_FLAGS[key]);
  }
  return args;
}

/** The reason a graph's crawl polled no device (its crawl_empty warning), or null. */
export function emptyCrawl(doc: unknown): string | null {
  const warnings = (doc as { metadata?: { warnings?: unknown } })?.metadata?.warnings;
  const hit = Array.isArray(warnings) ? warnings.find((w) => w?.type === 'crawl_empty') : undefined;
  return hit ? String(hit.reason ?? 'no device answered') : null;
}

/**
 * Whether a finished scan's graph may replace the current one: not when its
 * crawl polled no device while the current map has devices (a wrong community
 * or an unreachable gateway would otherwise wipe a good map), unless forced. Pure.
 */
export function shouldReplaceGraph(next: unknown, current: unknown, force: boolean): boolean {
  if (force || emptyCrawl(next) === null) return true;
  const nodes = (current as { nodes?: unknown })?.nodes;
  return !(Array.isArray(nodes) && nodes.some((n) => n?.kind === 'device'));
}

let onScanDone: ScanOptions['onDone'];

function finish(status: ScanState['status'], message: string) {
  scan = { ...scan, status, message, stage: null, finishedAt: new Date().toISOString() };
  const done = onScanDone;
  onScanDone = undefined;
  done?.(status !== 'failed', message);
}

/**
 * Start `<pythonBin> -m vulnmapper` in backendDir. Returns false if a scan (or
 * a runExclusive task) is already running. The graph JSON arrives on stdout; it is validated and then
 * written to a temp file and renamed over graphPath, so a failed or partial scan
 * always leaves the previous graph in place. The full CVE list goes to
 * vulnerabilities.json beside graphPath: the scanner writes it to a temp path,
 * which is moved into place only after the graph has been saved and deleted if
 * the scan or the save fails, so the two files always come from the same scan.
 * attack_paths.json (computed from targets.json beside the graph) is handled
 * the same way. A scan whose three files were all saved is then archived in
 * the scan history (history.ts); a failed one is not.
 */
export function startScan({
  pythonBin,
  backendDir,
  graphPath,
  community,
  deviceCves = true,
  checks = {},
  seeds = [],
  replaceEmpty = false,
  timeoutSeconds = 1800,
  trigger = 'manual',
  onDone,
  logger,
}: ScanOptions) {
  if (scan.status === 'running' || exclusiveTask) return false;
  scan = { status: 'running', trigger, message: null, stage: null, startedAt: new Date().toISOString(), finishedAt: null };
  onScanDone = onDone;
  // A scan started without one falls back to the environment; keep the last
  // community that was given rather than forgetting it.
  if (community) lastCommunity = community;
  lastChecks = checks;

  // The community goes to the scanner through the environment, never argv (argv
  // is visible to every user via ps). It is never logged. With no community the
  // scanner falls back to the SNMP_* variables already in the environment.
  const env = { ...process.env };
  if (community) env.VULNMAPPER_SNMP_COMMUNITY = community; // passed unsplit

  const vulnsPath = vulnerabilitiesFilePath(graphPath);
  const vulnsTmp = `${vulnsPath}.tmp-${process.pid}`;
  const pathsPath = attackPathsFilePath(graphPath);
  const pathsTmp = `${pathsPath}.tmp-${process.pid}`;
  const discardVulns = () =>
    Promise.all([vulnsTmp, pathsTmp].map((f) => fs.unlink(f).catch(() => undefined)));
  // The NVD answer cache (nvd-cache.json) sits beside the vulnerabilities file,
  // i.e. beside graphPath; NVD_API_KEY, if set, reaches the scanner through the
  // environment like the other credentials.
  const args = scanArgs({ vulns: vulnsTmp, paths: pathsTmp, targets: targetsFilePath(graphPath) }, { deviceCves, checks, seeds });
  logger.info(`scan started: ${pythonBin} ${args.join(' ')} (cwd ${backendDir})`);
  const child = spawn(pythonBin, args, { cwd: backendDir, env });
  const chunks: Buffer[] = [];
  let stderr = '';
  let partial = ''; // a stderr line not yet ended
  child.stdout.on('data', (d: Buffer) => chunks.push(d));
  child.stderr.on('data', (d: Buffer) => {
    const text = d.toString();
    stderr += text;
    const lines = (partial + text).split('\n');
    partial = lines.pop() || '';
    const stage = latestStage(lines.join('\n'));
    if (stage && scan.status === 'running') scan = { ...scan, stage };
  });

  // A hung scan (a stuck SNMP or TLS call) would otherwise hold the lock, and
  // refuse every later scan and protected-asset change, until a restart.
  let timedOut = false;
  let hardKill: NodeJS.Timeout | undefined;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill('SIGTERM');
    hardKill = setTimeout(() => child.kill('SIGKILL'), 10_000);
  }, timeoutSeconds * 1000);
  const stopTimers = () => {
    clearTimeout(timer);
    if (hardKill) clearTimeout(hardKill);
  };

  child.on('error', (e: Error) => {
    stopTimers();
    // The binary itself could not be launched (missing python, bad cwd).
    finish('failed', `failed to start ${pythonBin}: ${e.message}`);
    logger.warn(`scan failed: ${scan.message}`);
    discardVulns();
  });

  child.on('close', async (code: number | null) => {
    stopTimers();
    if (scan.status !== 'running') return; // spawn error already recorded
    if (timedOut) {
      await discardVulns(); // before finish releases the lock to the next scan
      finish('failed', `scan timed out after ${timeoutSeconds} s`);
      logger.warn(`scan failed: ${scan.message}`);
      return;
    }
    const out = Buffer.concat(chunks);
    if (code !== 0 || !out.length) {
      finish('failed', failureMessage(stderr, code, community));
      logger.warn(`scan failed: ${scan.message}`);
      await discardVulns();
      return;
    }
    let doc: unknown;
    try {
      doc = JSON.parse(out.toString()); // validate before replacing the good file
    } catch (e) {
      finish('failed', `could not save scanner output: ${(e as Error).message}`);
      logger.warn(`scan failed: ${scan.message}`);
      await discardVulns();
      return;
    }
    const current = await fs.readFile(graphPath, 'utf-8').then(JSON.parse).catch(() => null);
    if (!shouldReplaceGraph(doc, current, replaceEmpty)) {
      finish(
        'failed',
        `The network crawl polled no device (${emptyCrawl(doc)}), so the previous map was kept. Check the SNMP ` +
          'credential and vulnmapper.seeds, or turn on "Replace the map even if no device answered".'
      );
      logger.warn(`scan failed: ${scan.message}`);
      await discardVulns();
      return;
    }
    try {
      const tmp = `${graphPath}.tmp-${process.pid}`;
      await fs.writeFile(tmp, out);
      await fs.rename(tmp, graphPath);
    } catch (e) {
      finish('failed', `could not save scanner output: ${(e as Error).message}`);
      logger.warn(`scan failed: ${scan.message}`);
      await discardVulns();
      return;
    }
    try {
      await fs.rename(vulnsTmp, vulnsPath);
      // absent only when the scanner skipped the attack-path stage
      await fs.rename(pathsTmp, pathsPath).catch((e) => {
        if (e.code !== 'ENOENT') throw e;
      });
      finish('idle', 'Scan completed; graph updated.');
      logger.info('scan completed; graph updated');
      archiveScan(graphPath, trigger).catch((e) =>
        logger.warn(`scan completed, but it could not be added to the scan history: ${(e as Error).message}`)
      );
    } catch (e) {
      // The graph is saved; only the full CVE list is stale.
      finish('idle', `Scan completed; graph updated, but vulnerabilities.json or attack_paths.json was not: ${(e as Error).message}`);
      logger.warn(`could not save vulnerabilities.json / attack_paths.json: ${(e as Error).message}`);
      await discardVulns();
    }
  });

  return true;
}
