import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'fs';
import http from 'http';
import { AddressInfo } from 'net';
import os from 'os';
import path from 'path';
import { defineRoutes } from './routes';
import { nvdKeyPath, nvdKeyStatus, removeNvdKey, saveNvdKey, testNvdKey, withNvdKey } from './nvdKey';
import { recomputeAttackPaths } from './targets';

const KEY = '01234567-89ab-cdef-0123-456789abcdef';
const ENV_KEY = 'fedcba98-7654-3210-fedc-ba9876543210';
const graphIn = (dir: string) => path.join(dir, 'graph.json');
const tmp = () => mkdtempSync(path.join(os.tmpdir(), 'vm-nvd-'));

describe('the saved NVD key', () => {
  it('checks the shape, saves with mode 600 and removes', async () => {
    const graph = graphIn(tmp());
    expect(await saveNvdKey(graph, 'not-a-key')).toBe(false);
    expect(await saveNvdKey(graph, `${KEY}0`)).toBe(false);
    expect(nvdKeyStatus(graph, {})).toEqual({ source: 'none', savedAt: null });
    expect(await saveNvdKey(graph, ` ${KEY}\n`)).toBe(true);
    expect(readFileSync(nvdKeyPath(graph), 'utf-8')).toBe(KEY);
    expect(statSync(nvdKeyPath(graph)).mode & 0o777).toBe(0o600);
    expect(nvdKeyStatus(graph, {})).toMatchObject({ source: 'saved' });
    await removeNvdKey(graph);
    await removeNvdKey(graph); // already gone: fine
    expect(nvdKeyStatus(graph, { NVD_API_KEY: ENV_KEY })).toEqual({ source: 'env', savedAt: null });
  });

  it('beats the environment key, which passes through when nothing is saved', async () => {
    const graph = graphIn(tmp());
    expect(withNvdKey(graph, { NVD_API_KEY: ENV_KEY, OTHER: 'x' })).toEqual({ NVD_API_KEY: ENV_KEY, OTHER: 'x' });
    expect(withNvdKey(graph, {}).NVD_API_KEY).toBeUndefined();
    await saveNvdKey(graph, KEY);
    expect(withNvdKey(graph, { NVD_API_KEY: ENV_KEY, OTHER: 'x' })).toEqual({ NVD_API_KEY: KEY, OTHER: 'x' });
    const status = nvdKeyStatus(graph, { NVD_API_KEY: ENV_KEY });
    expect(status.source).toBe('saved');
    expect(JSON.stringify(status)).not.toContain(KEY);
  });

  it('reaches the rescore in its environment, never in argv', async () => {
    const dir = tmp();
    const graph = graphIn(dir);
    await saveNvdKey(graph, KEY);
    const child = path.join(dir, 'child.sh'); // records its key and arguments
    writeFileSync(child, `#!/bin/sh\necho "$NVD_API_KEY" > "${dir}/env"\necho "$@" > "${dir}/argv"\n`, { mode: 0o755 });
    const logger = { info: jest.fn(), warn: jest.fn() } as any;
    await recomputeAttackPaths({ pythonBin: child, backendDir: dir, graphPath: graph, rescore: true, logger });
    expect(readFileSync(path.join(dir, 'env'), 'utf-8')).toBe(`${KEY}\n`);
    expect(readFileSync(path.join(dir, 'argv'), 'utf-8')).not.toContain(KEY);
    expect(logger.info.mock.calls.join(' ')).not.toContain(KEY);
  });
});

describe('testNvdKey against a fake NVD', () => {
  let server: http.Server;
  let url: string;
  const seen: Array<string | undefined> = [];
  beforeAll(async () => {
    server = http.createServer((req, res) => {
      seen.push(req.headers.apikey as string | undefined);
      res.statusCode = req.headers.apikey === KEY ? 200 : 401;
      res.end('{}');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/rest/json/cves/2.0?cveId=CVE-2021-44228`;
  });
  afterAll(() => server.close());

  it('says valid, invalid or unreachable, sending the key in the apiKey header', async () => {
    expect(await testNvdKey(KEY, url)).toBe('valid');
    expect(await testNvdKey(ENV_KEY, url)).toBe('invalid');
    expect(seen).toEqual([KEY, ENV_KEY]);
    expect(await testNvdKey(KEY, 'http://127.0.0.1:1/')).toBe('unreachable');
  });

  it('is a route that never echoes the key, beside save, status and remove', async () => {
    const graph = graphIn(tmp());
    const handlers: Record<string, any> = {};
    const add = (method: string) => (cfg: { path: string }, h: any) => (handlers[`${method} ${cfg.path}`] = h);
    const router = { get: add('GET'), post: add('POST'), delete: add('DELETE'), put: add('PUT') } as any;
    const logger = { info: jest.fn(), warn: jest.fn(), debug: jest.fn() } as any;
    defineRoutes(router, { graphPath: graph, liveness: {}, seeds: [] } as any, logger, null, url);
    const response = {
      ok: ({ body }: any) => ({ status: 200, body }),
      badRequest: ({ body }: any) => ({ status: 400, body }),
      customError: ({ statusCode, body }: any) => ({ status: statusCode, body }),
    };
    const call = (route: string, body?: unknown) => handlers[route]({}, { body }, response);
    const KEY_URL = '/api/vulnmapper/settings/nvd-key';

    expect((await call(`POST ${KEY_URL}`, { key: 'nope' })).status).toBe(400);
    const saved = await call(`POST ${KEY_URL}`, { key: KEY });
    expect(saved.body.source).toBe('saved');
    const got = await call(`GET ${KEY_URL}`);
    expect(Object.keys(got.body).sort()).toEqual(['savedAt', 'source']);
    expect(await call(`POST ${KEY_URL}/test`, null)).toEqual({ status: 200, body: { result: 'valid' } });
    expect(await call(`POST ${KEY_URL}/test`, { key: ENV_KEY })).toEqual({ status: 200, body: { result: 'invalid' } });
    for (const r of [saved, got]) expect(JSON.stringify(r)).not.toContain(KEY);
    expect(logger.info.mock.calls.join(' ')).not.toContain(KEY);
    expect((await call(`DELETE ${KEY_URL}`)).body.source).not.toBe('saved');
  });
});
