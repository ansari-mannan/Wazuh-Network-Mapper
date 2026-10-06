import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';
import { Logger } from '../../../src/core/server';
import { VulnmapperConfig } from './config';
import { getScan, getLastCommunity } from './scan';

let timer: NodeJS.Timeout | null = null;
let running = false;

export function startLiveness(config: VulnmapperConfig, logger: Logger) {
  if (timer) return;
  const { backendDir, graphPath, liveness } = config;
  if (!liveness?.enabled || !backendDir || !graphPath) return;

  const interval = Math.max(10, liveness.intervalSeconds) * 1000;

  timer = setInterval(async () => {
    if (running || getScan().status === 'running') return;
    try {
      if (!(await fs.stat(graphPath))) return;
    } catch { return; }

    running = true;
    const livenessPath = liveness.path || path.join(path.dirname(graphPath), 'liveness.json');
    const env = { ...process.env };
    const community = getLastCommunity();
    if (community) env.SNMP_COMMUNITIES = community;

    const child = spawn(config.pythonBin, [
      '-m', 'vulnmapper.liveness',
      '--graph', graphPath,
      '--state', livenessPath,
      '--threshold', liveness.missThreshold.toString()
    ], { cwd: backendDir, env });

    let out = '';
    child.stdout.on('data', (d) => out += d.toString());

    // Timeout
    const timeout = setTimeout(() => child.kill(), Math.max(10, liveness.intervalSeconds) * 1000);

    child.on('close', async (code) => {
      clearTimeout(timeout);
      running = false;
      if (code !== 0) {
        logger.warn('liveness pass failed');
        return;
      }
      try {
        JSON.parse(out);
        const tmp = `${livenessPath}.tmp-${process.pid}`;
        await fs.writeFile(tmp, out);
        await fs.rename(tmp, livenessPath);
        logger.debug('liveness pass completed');
      } catch (e) {
        logger.warn(`liveness failed: ${(e as Error).message}`);
      }
    });

  }, interval);
}

export function stopLiveness() {
  if (timer) clearInterval(timer);
  timer = null;
}
