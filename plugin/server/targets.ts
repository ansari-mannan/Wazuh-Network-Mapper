import { spawn } from 'child_process';
import path from 'path';
import { Logger } from '../../../src/core/server';
import { Importance } from '../common';

// The owner's protected assets (targets.json) and the computed routes
// (attack_paths.json) both live beside the graph, as the Python engine expects.
export function targetsFilePath(graphPath: string): string {
  return path.join(path.dirname(path.resolve(graphPath)), 'targets.json');
}

export function attackPathsFilePath(graphPath: string): string {
  return path.join(path.dirname(path.resolve(graphPath)), 'attack_paths.json');
}

export type TargetEntry = { importance: Importance; note?: string };
export type TargetsFile = Record<string, TargetEntry>;

// The note left on an asset marked from the UI (the sample file's notes explain
// the format; a user's mark just records where it came from).
const UI_NOTE = 'Marked as a protected asset from the topology map.';

/**
 * Add, change the importance of, or (importance null) remove one target. A
 * changed entry keeps its existing note; a new one gets the UI note. Pure.
 */
export function applyTarget(current: TargetsFile, id: string, importance: Importance | null): TargetsFile {
  const next = { ...current };
  if (importance === null) {
    delete next[id];
  } else {
    next[id] = { importance, note: current[id]?.note ?? UI_NOTE };
  }
  return next;
}

/**
 * Run `<pythonBin> -m vulnmapper.attackpaths --graph <graphPath>` in backendDir,
 * which rewrites attack_paths.json (and reads targets.json) beside the graph.
 * No credential is passed: the path is the only argument. Resolves on success,
 * rejects with the scanner's last stderr line otherwise.
 */
export function recomputeAttackPaths({
  pythonBin,
  backendDir,
  graphPath,
  logger,
}: {
  pythonBin: string;
  backendDir: string;
  graphPath: string;
  logger: Logger;
}): Promise<void> {
  return new Promise((resolve, reject) => {
    const args = ['-m', 'vulnmapper.attackpaths', '--graph', graphPath];
    logger.info(`attack-paths recompute: ${pythonBin} ${args.join(' ')} (cwd ${backendDir})`);
    const child = spawn(pythonBin, args, { cwd: backendDir });
    let stderr = '';
    child.stderr.on('data', (d: Buffer) => {
      stderr += d.toString();
    });
    child.on('error', (e: Error) => reject(new Error(`failed to start ${pythonBin}: ${e.message}`)));
    child.on('close', (code: number | null) => {
      if (code === 0) return resolve();
      const lines = stderr.split('\n').map((l) => l.trim()).filter(Boolean);
      reject(new Error(lines.length ? lines[lines.length - 1] : `recompute exited with code ${code}`));
    });
  });
}
