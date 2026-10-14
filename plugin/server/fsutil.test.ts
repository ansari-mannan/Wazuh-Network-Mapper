import { mkdtempSync, promises as fs, readdirSync } from 'fs';
import os from 'os';
import path from 'path';
import { withFileLock, writeFileAtomic } from './fsutil';

describe('withFileLock', () => {
  it('keeps both of two overlapping read-modify-write updates', async () => {
    const file = path.join(mkdtempSync(path.join(os.tmpdir(), 'vm-lock-')), 'r.json');
    await fs.writeFile(file, '{}');
    const update = (key: string) =>
      withFileLock(file, async () => {
        const doc = JSON.parse(await fs.readFile(file, 'utf-8'));
        await new Promise((r) => setTimeout(r, 20)); // both would read before either writes
        await writeFileAtomic(file, JSON.stringify({ ...doc, [key]: true }));
      });
    await Promise.all([update('a'), update('b')]);
    expect(JSON.parse(await fs.readFile(file, 'utf-8'))).toEqual({ a: true, b: true });
  });

  it('runs the next update after one that failed', async () => {
    const file = path.join(os.tmpdir(), 'vm-lock-fail.json');
    await expect(withFileLock(file, async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    await expect(withFileLock(file, async () => 'ok')).resolves.toBe('ok');
  });
});

describe('writeFileAtomic', () => {
  it('leaves no temp file behind', async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'vm-atomic-'));
    await Promise.all([writeFileAtomic(path.join(dir, 'f'), '1'), writeFileAtomic(path.join(dir, 'f'), '2')]);
    expect(readdirSync(dir)).toEqual(['f']);
  });
});
