import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import { Logger } from '../../../src/core/server';
import { ScanState } from '../common';

// Ported from frontend/app/api/scan/route.ts and frontend/lib/scanState.ts.
// One module-level state object: the server process runs one scan at a time.
let scan: ScanState = { status: 'idle', message: null, startedAt: null, finishedAt: null };

export function getScan(): ScanState {
  return scan;
}

interface ScanOptions {
  pythonBin: string;
  backendDir: string;
  graphPath: string;
  community?: string;
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

function finish(status: ScanState['status'], message: string) {
  scan = { ...scan, status, message, finishedAt: new Date().toISOString() };
}

/**
 * Start `<pythonBin> -m vulnmapper` in backendDir. Returns false if a scan is
 * already running. The graph JSON arrives on stdout; it is validated and then
 * written to a temp file and renamed over graphPath, so a failed or partial scan
 * always leaves the previous graph in place.
 */
export function startScan({ pythonBin, backendDir, graphPath, community, logger }: ScanOptions) {
  if (scan.status === 'running') return false;
  scan = { status: 'running', message: null, startedAt: new Date().toISOString(), finishedAt: null };

  // The community goes to the scanner through the environment, never argv (argv
  // is visible to every user via ps). It is never logged. With no community the
  // scanner falls back to the SNMP_* variables already in the environment.
  const env = { ...process.env };
  if (community) env.SNMP_COMMUNITIES = community;

  logger.info(`scan started: ${pythonBin} -m vulnmapper (cwd ${backendDir})`);
  const child = spawn(pythonBin, ['-m', 'vulnmapper'], { cwd: backendDir, env });
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
  });

  child.on('close', async (code: number | null) => {
    if (scan.status !== 'running') return; // spawn error already recorded
    const out = Buffer.concat(chunks);
    if (code !== 0 || !out.length) {
      finish('failed', failureMessage(stderr, code, community));
      logger.warn(`scan failed: ${scan.message}`);
      return;
    }
    try {
      JSON.parse(out.toString()); // validate before replacing the good file
      const tmp = `${graphPath}.tmp-${process.pid}`;
      await fs.writeFile(tmp, out);
      await fs.rename(tmp, graphPath);
      finish('idle', 'Scan completed; graph updated.');
      logger.info('scan completed; graph updated');
    } catch (e) {
      finish('failed', `could not save scanner output: ${(e as Error).message}`);
      logger.warn(`scan failed: ${scan.message}`);
    }
  });

  return true;
}
