import { promises as fs } from 'fs';
import { schema } from '@osd/config-schema';
import { IRouter, Logger } from '../../../../src/core/server';
import { LivenessResponse, ScanState } from '../../common';
import { configuredChecks, VulnmapperConfig } from '../config';
import { livenessPath } from '../liveness';
import { getScan, startScan } from '../scan';

export function defineRoutes(router: IRouter, config: VulnmapperConfig, logger: Logger) {
  const notConfigured = (key: string) => ({
    statusCode: 500,
    body: { message: `vulnmapper.${key} is not set in opensearch_dashboards.yml` },
  });

  // The scan state, with the defaults the scan form starts from.
  const scanBody = (): ScanState => ({
    ...getScan(),
    defaults: configuredChecks(config),
  });

  // The graph is read fresh from disk on every request so the file the scanner
  // writes stays the single source of truth (same as frontend/app/api/graph).
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
        },
        pythonBin,
        backendDir,
        graphPath,
        community: request.body?.community || undefined,
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
