// The NVD API key saved from Scan settings: the file nvd-key beside the graph
// (mode 600). A saved key beats NVD_API_KEY from the server's environment; it
// reaches the scanner and the rescore only in the child's environment, never
// argv, a log or an API response.
import { promises as fs, readFileSync, statSync } from 'fs';
import http from 'http';
import https from 'https';
import path from 'path';
import { writeFileAtomic } from './fsutil';

// NVD keys are UUIDs (36 characters).
export const NVD_KEY_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// One small, always-present record; the answer's content is not read.
export const NVD_TEST_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228';

export type NvdKeySource = 'saved' | 'env' | 'none';
export type NvdKeyTest = 'valid' | 'invalid' | 'unreachable';

export const nvdKeyPath = (graphPath: string) => path.join(path.dirname(path.resolve(graphPath)), 'nvd-key');

/** The saved key, or null when there is none (or it cannot be read). */
export function savedNvdKey(graphPath: string): string | null {
  try {
    return readFileSync(nvdKeyPath(graphPath), 'utf-8').trim() || null;
  } catch {
    return null;
  }
}

/** env for a child process: NVD_API_KEY is the saved key when there is one, else env's own. */
export function withNvdKey(graphPath: string | null | undefined, env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const saved = graphPath ? savedNvdKey(graphPath) : null;
  return saved ? { ...env, NVD_API_KEY: saved } : { ...env };
}

/** Where the key the scanner uses comes from, and when it was saved; never the key. */
export function nvdKeyStatus(graphPath: string, env: NodeJS.ProcessEnv = process.env): { source: NvdKeySource; savedAt: string | null } {
  if (savedNvdKey(graphPath)) {
    let savedAt: string | null = null;
    try {
      savedAt = statSync(nvdKeyPath(graphPath)).mtime.toISOString();
    } catch {
      // removed meanwhile: the date is unknown
    }
    return { source: 'saved', savedAt };
  }
  return { source: (env.NVD_API_KEY || '').trim() ? 'env' : 'none', savedAt: null };
}

/** Save a key of the right shape (atomically, mode 600); false when the shape is wrong. */
export async function saveNvdKey(graphPath: string, key: string): Promise<boolean> {
  const trimmed = key.trim();
  if (!NVD_KEY_SHAPE.test(trimmed)) return false;
  await writeFileAtomic(nvdKeyPath(graphPath), trimmed, 0o600);
  return true;
}

export async function removeNvdKey(graphPath: string): Promise<void> {
  await fs.unlink(nvdKeyPath(graphPath)).catch((e) => {
    if (e.code !== 'ENOENT') throw e;
  });
}

/**
 * One NVD request with key in the apiKey header: 200 is valid, 401 or 404 (NVD's
 * answer to an unknown key) invalid, anything else (no answer, a rate limit, a
 * server error) unreachable. The key is never part of the result.
 */
export function testNvdKey(key: string, url = NVD_TEST_URL, timeoutMs = 15000): Promise<NvdKeyTest> {
  const get = url.startsWith('https:') ? https.get : http.get;
  return new Promise((resolve) => {
    const req = get(url, { headers: { apiKey: key }, timeout: timeoutMs }, (res) => {
      res.resume();
      const status = res.statusCode;
      resolve(status === 200 ? 'valid' : status === 401 || status === 404 ? 'invalid' : 'unreachable');
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve('unreachable'));
  });
}
