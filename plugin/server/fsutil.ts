// Small file helpers for the server: a per-file lock for read-modify-write,
// and an atomic write (temp file, then rename) whose temp name is unique, so
// two writes of one file never share a temp file.
import { promises as fs } from 'fs';

const chains = new Map<string, Promise<unknown>>();

/** Run fn after every earlier fn for the same file has settled (a promise chain). */
export function withFileLock<T>(file: string, fn: () => Promise<T>): Promise<T> {
  const run = (chains.get(file) ?? Promise.resolve()).then(fn, fn);
  const tail = run.catch(() => undefined);
  chains.set(file, tail);
  tail.then(() => {
    if (chains.get(file) === tail) chains.delete(file);
  });
  return run;
}

let counter = 0;

/** Write data to file through a unique temp file in the same folder, then rename. */
export async function writeFileAtomic(file: string, data: string | Buffer): Promise<void> {
  counter += 1;
  const tmp = `${file}.tmp-${process.pid}-${counter}`;
  try {
    await fs.writeFile(tmp, data);
    await fs.rename(tmp, file);
  } catch (e) {
    await fs.unlink(tmp).catch(() => undefined);
    throw e;
  }
}
