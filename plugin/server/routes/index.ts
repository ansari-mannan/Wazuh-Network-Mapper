// The plugin's HTTP API: the graph and the other files beside it, starting a
// scan, its status, schedule and history, liveness, protected assets and
// recommendation statuses.
import { promises as fs } from 'fs';
import { schema } from '@osd/config-schema';
import { IRouter, Logger } from '../../../../src/core/server';
import { LivenessResponse, ScanState } from '../../common';
import { configuredChecks, VulnmapperConfig } from '../config';
import { livenessPath } from '../liveness';
import { getScan, onPath, runExclusive, startScan } from '../scan';
import { scheduleBody, Scheduler } from '../schedule';
import { historyDir, historyParams, readChanges, readIndex } from '../history';
import { attackPathsFilePath, recomputeAttackPaths, targetsFilePath, updateTarget, vulnerabilitiesFilePath } from '../targets';
import { applyRecommendationStatus, readRecommendations, recommendationsFilePath } from '../recommendations';

export function defineRoutes(
  router: IRouter,
  config: VulnmapperConfig,
  logger: Logger,
  scheduler: Scheduler | null = null
) {
  const notConfigured = (key: string) => ({
    statusCode: 500,
    body: { message: `vulnmapper.${key} is not set in opensearch_dashboards.yml` },
  });

  // The scan state, with the defaults the scan form starts from.
  const scanBody = (): ScanState => ({
    ...getScan(),
    defaults: configuredChecks(config),
    nmapAvailable: onPath('nmap'),
    seeds: config.seeds,
  });

  // The graph is read fresh from disk on every request so the file the scanner
  // writes stays the single source of truth.
  // The file's mtime is returned in a header for the "where the graph came from" view.
  router.get(
    { path: '/api/vulnmapper/graph', validate: false },
    async (context, request, response) => {
      const graphPath = config.graphPath;
      if (!graphPath) return response.customError(notConfigured('graphPath'));
      let data: string;
      let mtime: Date;
      try {
        [data, { mtime }] = await Promise.all([
          fs.readFile(graphPath, 'utf-8'),
          fs.stat(graphPath),
        ]);
      } catch (err) {
        return response.notFound({
          body: { message: `Could not read graph at ${graphPath}: ${(err as Error).message}` },
        });
      }
      try {
        return response.ok({
          body: JSON.parse(data),
          headers: { 'x-vulnmapper-graph-mtime': mtime.toISOString() },
        });
      } catch (err) {
        return response.customError({
          statusCode: 500,
          body: { message: `graph.json is not valid JSON: ${(err as Error).message}` },
        });
      }
    }
  );

  // The attack-paths document, read fresh from disk beside the graph (like the
  // graph route). A missing file is "not computed yet", returned as a small doc
  // with metadata.state 'absent' rather than an error, so the UI can offer a scan.
  router.get(
    { path: '/api/vulnmapper/attack-paths', validate: false },
    async (context, request, response) => {
      const { graphPath } = config;
      if (!graphPath) return response.customError(notConfigured('graphPath'));
      const file = attackPathsFilePath(graphPath);
      let data: string;
      try {
        data = await fs.readFile(file, 'utf-8');
      } catch {
        return response.ok({ body: { metadata: { state: 'absent' }, targets: [], starting_points: [], per_asset: [], not_placed: [] } });
      }
      try {
        return response.ok({ body: JSON.parse(data) });
      } catch (err) {
        return response.customError({
          statusCode: 500,
          body: { message: `attack_paths.json is not valid JSON: ${(err as Error).message}` },
        });
      }
    }
  );

  // The full per-asset CVE list (vulnerabilities.json beside the graph, like
  // the attack-paths route). A missing file is "not produced yet", returned as
  // an empty doc with metadata.state 'absent' so the report shows a clean
  // "not available" state rather than an error. The report's organisation name
  // (config vulnmapper.reportOrg) is injected here; it is not part of the file.
  router.get(
    { path: '/api/vulnmapper/vulnerabilities', validate: false },
    async (context, request, response) => {
      const { graphPath } = config;
      if (!graphPath) return response.customError(notConfigured('graphPath'));
      const file = vulnerabilitiesFilePath(graphPath);
      let data: string;
      try {
        data = await fs.readFile(file, 'utf-8');
      } catch {
        return response.ok({ body: { metadata: { state: 'absent' }, cves: {}, hosts: {}, org: config.reportOrg } });
      }
      try {
        return response.ok({ body: { ...JSON.parse(data), org: config.reportOrg } });
      } catch (err) {
        return response.customError({
          statusCode: 500,
          body: { message: `vulnerabilities.json is not valid JSON: ${(err as Error).message}` },
        });
      }
    }
  );

  // Mark, re-rate or unmark one protected asset (targets.json beside the graph),
  // then rescore: importance is an OVSS input, so graph.json and
  // vulnerabilities.json are rescored and attack_paths.json recomputed, from
  // cached threat data only. importance null unmarks. Under the scan lock:
  // 409 while a scan or another update runs.
  // No credential is passed; marking needs no network scan, so this is quick.
  router.post(
    {
      path: '/api/vulnmapper/targets',
      validate: {
        body: schema.object({
          id: schema.string({ minLength: 1, maxLength: 512 }),
          importance: schema.nullable(
            schema.oneOf([schema.literal('high'), schema.literal('moderate'), schema.literal('low')])
          ),
        }),
      },
    },
    async (context, request, response) => {
      const { backendDir, graphPath, pythonBin } = config;
      if (!backendDir) return response.customError(notConfigured('backendDir'));
      if (!graphPath) return response.customError(notConfigured('graphPath'));
      const file = targetsFilePath(graphPath);
      const result = await updateTarget(
        {
          runExclusive,
          read: async () => {
            try {
              return JSON.parse(await fs.readFile(file, 'utf-8'));
            } catch {
              return {}; // no targets file yet: start from nothing
            }
          },
          write: async (next) => {
            const tmp = `${file}.tmp-${process.pid}`;
            await fs.writeFile(tmp, JSON.stringify(next, null, 2));
            await fs.rename(tmp, file);
          },
          recompute: () =>
            recomputeAttackPaths({
              pythonBin,
              backendDir,
              graphPath,
              livenessFile: config.liveness.enabled ? livenessPath(config) : null,
              rescore: true,
              logger,
            }),
        },
        request.body.id,
        request.body.importance
      );
      if (result.status !== 200) {
        return response.customError({ statusCode: result.status, body: { message: result.message } });
      }
      return response.ok({ body: { targets: result.targets } });
    }
  );

  // The shared recommendations tracker (recommendations.json beside the graph).
  // GET returns the file ({ statuses: {} } when absent). Read fresh from disk,
  // like the other routes.
  router.get(
    { path: '/api/vulnmapper/recommendations', validate: false },
    async (context, request, response) => {
      const { graphPath } = config;
      if (!graphPath) return response.customError(notConfigured('graphPath'));
      let data: string | null = null;
      try {
        data = await fs.readFile(recommendationsFilePath(graphPath), 'utf-8');
      } catch {
        // no tracker yet: an empty one
      }
      return response.ok({ body: readRecommendations(data) });
    }
  );

  // Set one item's status, then atomically rewrite the tracker. This writes a
  // local file only: it never scans, spawns a process, or puts anything in argv.
  router.post(
    {
      path: '/api/vulnmapper/recommendations/status',
      validate: {
        body: schema.object({
          key: schema.string({ minLength: 1, maxLength: 512 }),
          status: schema.oneOf([
            schema.literal('open'),
            schema.literal('in_progress'),
            schema.literal('done'),
            schema.literal('accepted_risk'),
          ]),
          // what the item covered when set, so a later scan that finds more reopens it
          affected: schema.maybe(schema.arrayOf(schema.string({ maxLength: 512 }), { maxSize: 100000 })),
          findings: schema.maybe(schema.number({ min: 0 })),
        }),
      },
    },
    async (context, request, response) => {
      const { graphPath } = config;
      if (!graphPath) return response.customError(notConfigured('graphPath'));
      const file = recommendationsFilePath(graphPath);
      let data: string | null = null;
      try {
        data = await fs.readFile(file, 'utf-8');
      } catch {
        // no tracker yet: start empty
      }
      const next = applyRecommendationStatus(readRecommendations(data), request.body.key, request.body.status, {
        affected: request.body.affected,
        findings: request.body.findings,
      });
      try {
        const tmp = `${file}.tmp-${process.pid}`;
        await fs.writeFile(tmp, JSON.stringify(next, null, 2));
        await fs.rename(tmp, file);
      } catch (e) {
        return response.customError({
          statusCode: 500,
          body: { message: `could not save recommendations: ${(e as Error).message}` },
        });
      }
      return response.ok({ body: next });
    }
  );

  router.post(
    {
      path: '/api/vulnmapper/scan',
      validate: {
        body: schema.nullable(
          schema.object({
            community: schema.maybe(schema.string({ maxLength: 256 })),
            checkDefaultCommunities: schema.maybe(schema.boolean()),
            checkManagementPorts: schema.maybe(schema.boolean()),
            probeUnmanagedSnmp: schema.maybe(schema.boolean()),
            nmapUnmanaged: schema.maybe(schema.boolean()),
            replaceEmpty: schema.maybe(schema.boolean()),
          })
        ),
      },
    },
    async (context, request, response) => {
      const { backendDir, graphPath, pythonBin } = config;
      if (!backendDir) return response.customError(notConfigured('backendDir'));
      if (!graphPath) return response.customError(notConfigured('graphPath'));
      const started = startScan({
        deviceCves: config.deviceCves,
        // the form's choices; the configured default for any it does not send
        checks: {
          checkDefaultCommunities: request.body?.checkDefaultCommunities ?? config.checkDefaultCommunities,
          checkManagementPorts: request.body?.checkManagementPorts ?? config.checkManagementPorts,
          probeUnmanagedSnmp: request.body?.probeUnmanagedSnmp ?? config.probeUnmanagedSnmp,
          nmapUnmanaged: request.body?.nmapUnmanaged ?? config.nmapUnmanaged,
        },
        pythonBin,
        backendDir,
        graphPath,
        community: request.body?.community || undefined,
        seeds: config.seeds,
        timeoutSeconds: config.scanTimeoutSeconds,
        replaceEmpty: request.body?.replaceEmpty ?? false,
        logger,
      });
      if (!started) {
        return response.customError({
          statusCode: 409,
          body: { message: 'a scan is already running' },
        });
      }
      return response.accepted({ body: scanBody() });
    }
  );

  // Scheduled scans: the choice, the next due time and the last scheduled run.
  // Needs backendDir and graphPath (schedule.json lives beside the graph).
  router.get(
    { path: '/api/vulnmapper/schedule', validate: false },
    async (context, request, response) => {
      if (!scheduler) return response.customError(notConfigured(config.backendDir ? 'graphPath' : 'backendDir'));
      return response.ok({ body: scheduler.get() });
    }
  );

  router.post(
    {
      path: '/api/vulnmapper/schedule',
      validate: {
        body: scheduleBody,
      },
    },
    async (context, request, response) => {
      if (!scheduler) return response.customError(notConfigured(config.backendDir ? 'graphPath' : 'backendDir'));
      await scheduler.set(request.body);
      return response.ok({ body: scheduler.get() });
    }
  );

  // The scan history's index (newest first; [] before the first archived scan).
  router.get(
    { path: '/api/vulnmapper/history', validate: false },
    async (context, request, response) => {
      if (!config.graphPath) return response.customError(notConfigured('graphPath'));
      return response.ok({ body: await readIndex(historyDir(config.graphPath)) });
    }
  );

  // One archived scan's files and the previous scan's, for "what changed".
  // The id must match the id format and be in the index (readChanges), so it
  // can never name another path.
  router.get(
    {
      path: '/api/vulnmapper/history/{id}/changes',
      validate: { params: historyParams },
    },
    async (context, request, response) => {
      if (!config.graphPath) return response.customError(notConfigured('graphPath'));
      try {
        const body = await readChanges(config.graphPath, request.params.id);
        if (!body) return response.notFound({ body: { message: 'no such scan in the history' } });
        return response.ok({ body });
      } catch (e) {
        return response.customError({
          statusCode: 500,
          body: { message: `could not read the archived scan: ${(e as Error).message}` },
        });
      }
    }
  );

  router.get(
    { path: '/api/vulnmapper/scan/status', validate: false },
    async (context, request, response) => response.ok({ body: scanBody() })
  );

  // Liveness state for the UI: { enabled, intervalSeconds, checkedAt, nodes,
  // graphMtime }. Disabled, or no pass saved yet: checkedAt null and no nodes.
  // Read fresh from disk, like the graph; an unreadable file reads as "no pass
  // yet". graphMtime is the graph file's modified time (null if there is no
  // file), so the UI can reload the graph after an automatic scan.
  router.get(
    { path: '/api/vulnmapper/liveness', validate: false },
    async (context, request, response) => {
      const { enabled, intervalSeconds } = config.liveness;
      const body: LivenessResponse = { enabled, intervalSeconds, checkedAt: null, nodes: {}, graphMtime: null };
      if (config.graphPath) {
        try {
          body.graphMtime = (await fs.stat(config.graphPath)).mtime.toISOString();
        } catch {
          // no graph yet
        }
      }
      const file = livenessPath(config);
      if (!enabled || !file) return response.ok({ body });
      try {
        const doc = JSON.parse(await fs.readFile(file, 'utf8'));
        if (doc && typeof doc.nodes === 'object' && !Array.isArray(doc.nodes)) {
          body.checkedAt = typeof doc.checked_at === 'string' ? doc.checked_at : null;
          body.nodes = doc.nodes;
        }
      } catch {
        // no pass yet
      }
      return response.ok({ body });
    }
  );
}
