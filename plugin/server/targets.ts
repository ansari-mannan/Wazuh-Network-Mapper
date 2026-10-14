// The owner's protected assets (targets.json) and the computed routes
// (attack_paths.json) both live beside the graph, as the Python engine expects.
import { spawn } from 'child_process';
import path from 'path';
import { Logger } from '../../../src/core/server';
import { Importance } from '../common';

export function targetsFilePath(graphPath: string): string {
  return path.join(path.dirname(path.resolve(graphPath)), 'targets.json');
}

export function vulnerabilitiesFilePath(graphPath: string): string {
  return path.join(path.dirname(path.resolve(graphPath)), 'vulnerabilities.json');
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
 * The backend command that refreshes the files after a change. Plain: only
 * attack_paths.json (`vulnmapper.attackpaths`, as after a liveness pass).
 * rescore: also the OVSS scores in graph.json and vulnerabilities.json, which
 * read each asset's importance (`vulnmapper.scoring.rescore`, after targets.json
 * changed); it uses the cached threat data and never downloads. Paths are the
 * only arguments: no credential is passed. Pure.
 */
export function recomputeArgs(graphPath: string, livenessFile?: string | null, rescore = false): string[] {
  const args = ['-m', rescore ? 'vulnmapper.scoring.rescore' : 'vulnmapper.attackpaths', '--graph', graphPath];
  if (livenessFile) args.push('--liveness', livenessFile);
  return args;
}

/**
 * Run recomputeArgs' command in backendDir. With livenessFile (liveness on),
 * hosts its pass marks inactive are not used as starts, provided the pass was
 * made for this graph. Resolves on success, rejects with the last stderr line
 * otherwise.
 */
export function recomputeAttackPaths({
  pythonBin,
  backendDir,
  graphPath,
  livenessFile,
  rescore = false,
  logger,
}: {
  pythonBin: string;
  backendDir: string;
  graphPath: string;
  livenessFile?: string | null;
  rescore?: boolean;
  logger: Logger;
}): Promise<void> {
  return new Promise((resolve, reject) => {
    const args = recomputeArgs(graphPath, livenessFile, rescore);
    logger.info(`${rescore ? 'rescore' : 'attack-paths recompute'}: ${pythonBin} ${args.join(' ')} (cwd ${backendDir})`);
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
