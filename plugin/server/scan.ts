import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';
import { Logger } from '../../../src/core/server';
import { ScanState } from '../common';

// Ported from frontend/app/api/scan/route.ts and frontend/lib/scanState.ts.
// One module-level state object: the server process runs one scan at a time.
let scan: ScanState = { status: 'idle', message: null, startedAt: null, finishedAt: null };
// The last community a scan was started with, for the liveness pass's SNMP
// probes. Memory only: never logged, written to disk or placed in argv.
let lastCommunity: string | undefined;
// The last scan's choice of the default-community probe, so an automatic rescan
// does not silently change it.
let lastCheckDefaultCommunities: boolean | undefined;

export function getScan(): ScanState {
  return scan;
}

export function getLastCommunity(): string | undefined {
  return lastCommunity;
}

export function getLastCheckDefaultCommunities(): boolean | undefined {
  return lastCheckDefaultCommunities;
}

interface ScanOptions {
  pythonBin: string;
  backendDir: string;
  graphPath: string;
  community?: string;
  // false: the scanner skips the device CVE stage (--no-device-cves)
  deviceCves?: boolean;
  // true: also try the factory SNMP names public and private (--check-default-communities)
  checkDefaultCommunities?: boolean;
  logger: Logger;
}

// The scanner logs to stderr and ends a failed run with one plain message line
// (e.g. "vulnmapper: WAZUH_PASS is not set; ..."), so the last non-empty line is
// the useful one to show. The community string is redacted in case it appears.
function failureMessage(stderr: string, code: number | null, community?: string): string {
  const lines = stderr.split('\n').map((l) => l.trim()).filter(Boolean);
  let msg = lines.length ? lines[lines.length - 1] : `scanner exited with code ${code}`;
  if (community) msg = msg.split(community).join('***');
  return msg;
}

/** The scanner's arguments. Never a credential: those go through the environment. */
export function scanArgs(
  vulnsOut: string,
  { deviceCves = true, checkDefaultCommunities = false }: { deviceCves?: boolean; checkDefaultCommunities?: boolean }
): string[] {
  const args = ['-m', 'vulnmapper', '--vulns-out', vulnsOut];
  if (!deviceCves) args.push('--no-device-cves');
  if (checkDefaultCommunities) args.push('--check-default-communities');
  return args;
}

function finish(status: ScanState['status'], message: string) {
  scan = { ...scan, status, message, finishedAt: new Date().toISOString() };
}

/**
 * Start `<pythonBin> -m vulnmapper` in backendDir. Returns false if a scan is
 * already running. The graph JSON arrives on stdout; it is validated and then
 * written to a temp file and renamed over graphPath, so a failed or partial scan
 * always leaves the previous graph in place. The full CVE list goes to
 * vulnerabilities.json beside graphPath: the scanner writes it to a temp path,
 * which is moved into place only after the graph has been saved and deleted if
 * the scan or the save fails, so the two files always come from the same scan.
 */
export function startScan({
  pythonBin,
  backendDir,
  graphPath,
  community,
  deviceCves = true,
  checkDefaultCommunities = false,
  logger,
}: ScanOptions) {
  if (scan.status === 'running') return false;
  scan = { status: 'running', message: null, startedAt: new Date().toISOString(), finishedAt: null };
  // A scan started without one falls back to the environment; keep the last
  // community that was given rather than forgetting it.
  if (community) lastCommunity = community;
  lastCheckDefaultCommunities = checkDefaultCommunities;

  // The community goes to the scanner through the environment, never argv (argv
  // is visible to every user via ps). It is never logged. With no community the
  // scanner falls back to the SNMP_* variables already in the environment.
  const env = { ...process.env };
  if (community) env.SNMP_COMMUNITIES = community;

  const vulnsPath = path.join(path.dirname(path.resolve(graphPath)), 'vulnerabilities.json');
  const vulnsTmp = `${vulnsPath}.tmp-${process.pid}`;
  const discardVulns = () => fs.unlink(vulnsTmp).catch(() => undefined);
  // The NVD answer cache (nvd-cache.json) sits beside the vulnerabilities file,
  // i.e. beside graphPath; NVD_API_KEY, if set, reaches the scanner through the
  // environment like the other credentials.
  const args = scanArgs(vulnsTmp, { deviceCves, checkDefaultCommunities });
  logger.info(`scan started: ${pythonBin} ${args.join(' ')} (cwd ${backendDir})`);
  const child = spawn(pythonBin, args, { cwd: backendDir, env });
  const chunks: Buffer[] = [];
  let stderr = '';
  child.stdout.on('data', (d: Buffer) => chunks.push(d));
  child.stderr.on('data', (d: Buffer) => {
    stderr += d.toString();
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
      finish('idle', 'Scan completed; graph updated.');
      logger.info('scan completed; graph updated');
    } catch (e) {
      // The graph is saved; only the full CVE list is stale.
      finish('idle', `Scan completed; graph updated, but vulnerabilities.json was not: ${(e as Error).message}`);
      logger.warn(`could not save vulnerabilities.json: ${(e as Error).message}`);
      await discardVulns();
    }
  });

  return true;
}
