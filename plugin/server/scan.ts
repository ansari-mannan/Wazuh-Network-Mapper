import { spawn } from 'child_process';
import { accessSync, constants, promises as fs } from 'fs';
import path from 'path';
import { Logger } from '../../../src/core/server';
import { ActiveChecks, ScanState } from '../common';
import { attackPathsFilePath, targetsFilePath, vulnerabilitiesFilePath } from './targets';

// Ported from frontend/app/api/scan/route.ts and frontend/lib/scanState.ts.
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
  // the optional active checks that are on (see CHECK_FLAGS)
  checks?: Partial<ActiveChecks>;
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
  { deviceCves = true, checks = {} }: { deviceCves?: boolean; checks?: Partial<ActiveChecks> }
): string[] {
  const args = ['-m', 'vulnmapper', '--vulns-out', out.vulns, '--paths-out', out.paths, '--targets', out.targets];
  if (!deviceCves) args.push('--no-device-cves');
  for (const key of Object.keys(CHECK_FLAGS) as Array<keyof ActiveChecks>) {
    if (checks[key]) args.push(CHECK_FLAGS[key]);
  }
  return args;
}

function finish(status: ScanState['status'], message: string) {
  scan = { ...scan, status, message, stage: null, finishedAt: new Date().toISOString() };
}

/**
 * Start `<pythonBin> -m vulnmapper` in backendDir. Returns false if a scan is
 * already running. The graph JSON arrives on stdout; it is validated and then
 * written to a temp file and renamed over graphPath, so a failed or partial scan
 * always leaves the previous graph in place. The full CVE list goes to
 * vulnerabilities.json beside graphPath: the scanner writes it to a temp path,
 * which is moved into place only after the graph has been saved and deleted if
 * the scan or the save fails, so the two files always come from the same scan.
 * attack_paths.json (computed from targets.json beside the graph) is handled
 * the same way.
 */
export function startScan({
  pythonBin,
  backendDir,
  graphPath,
  community,
  deviceCves = true,
  checks = {},
  logger,
}: ScanOptions) {
  if (scan.status === 'running') return false;
  scan = { status: 'running', message: null, stage: null, startedAt: new Date().toISOString(), finishedAt: null };
  // A scan started without one falls back to the environment; keep the last
  // community that was given rather than forgetting it.
  if (community) lastCommunity = community;
  lastChecks = checks;

  // The community goes to the scanner through the environment, never argv (argv
  // is visible to every user via ps). It is never logged. With no community the
  // scanner falls back to the SNMP_* variables already in the environment.
  const env = { ...process.env };
  if (community) env.SNMP_COMMUNITIES = community;

  const vulnsPath = vulnerabilitiesFilePath(graphPath);
  const vulnsTmp = `${vulnsPath}.tmp-${process.pid}`;
  const pathsPath = attackPathsFilePath(graphPath);
  const pathsTmp = `${pathsPath}.tmp-${process.pid}`;
  const discardVulns = () =>
    Promise.all([vulnsTmp, pathsTmp].map((f) => fs.unlink(f).catch(() => undefined)));
  // The NVD answer cache (nvd-cache.json) sits beside the vulnerabilities file,
  // i.e. beside graphPath; NVD_API_KEY, if set, reaches the scanner through the
  // environment like the other credentials.
  const args = scanArgs({ vulns: vulnsTmp, paths: pathsTmp, targets: targetsFilePath(graphPath) }, { deviceCves, checks });
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

  child.on('error', (e: Error) => {
    // The binary itself could not be launched (missing python, bad cwd).
    finish('failed', `failed to start ${pythonBin}: ${e.message}`);
    logger.warn(`scan failed: ${scan.message}`);
    discardVulns();
  });

  child.on('close', async (code: number | null) => {
    if (scan.status !== 'running') return; // spawn error already recorded
    const out = Buffer.concat(chunks);
    if (code !== 0 || !out.length) {
      finish('failed', failureMessage(stderr, code, community));
      logger.warn(`scan failed: ${scan.message}`);
      await discardVulns();
      return;
    }
    try {
      JSON.parse(out.toString()); // validate before replacing the good file
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
    } catch (e) {
      // The graph is saved; only the full CVE list is stale.
      finish('idle', `Scan completed; graph updated, but vulnerabilities.json or attack_paths.json was not: ${(e as Error).message}`);
      logger.warn(`could not save vulnerabilities.json / attack_paths.json: ${(e as Error).message}`);
      await discardVulns();
    }
  });

  return true;
}
