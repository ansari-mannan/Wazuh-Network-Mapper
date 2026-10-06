import { promises as fs } from 'fs';
import path from 'path';
import { schema } from '@osd/config-schema';
import { IRouter, Logger } from '../../../../src/core/server';
import { VulnmapperConfig } from '../config';
import { getScan, startScan } from '../scan';

export function defineRoutes(router: IRouter, config: VulnmapperConfig, logger: Logger) {
  const notConfigured = (key: string) => ({
    statusCode: 500,
    body: { message: `vulnmapper.${key} is not set in opensearch_dashboards.yml` },
  });

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
          schema.object({ community: schema.maybe(schema.string({ maxLength: 256 })) })
        ),
      },
    },
    async (context, request, response) => {
      const { backendDir, graphPath, pythonBin } = config;
      if (!backendDir) return response.customError(notConfigured('backendDir'));
      if (!graphPath) return response.customError(notConfigured('graphPath'));
      const started = startScan({
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
      return response.accepted({ body: getScan() });
    }
  );

  router.get(
    { path: '/api/vulnmapper/scan/status', validate: false },
    async (context, request, response) => response.ok({ body: getScan() })
  );

  router.get(
    { path: '/api/vulnmapper/liveness', validate: false },
    async (context, request, response) => {
      const livenessPath = config.liveness?.path || (config.graphPath ? path.join(path.dirname(config.graphPath), 'liveness.json') : null);
      if (!livenessPath) {
        return response.ok({ body: { enabled: config.liveness?.enabled, intervalSeconds: config.liveness?.intervalSeconds, checkedAt: null, nodes: {} } });
      }
      try {
        const data = await fs.readFile(livenessPath, 'utf-8');
        const json = JSON.parse(data);
        return response.ok({ body: { enabled: config.liveness?.enabled, intervalSeconds: config.liveness?.intervalSeconds, ...json } });
      } catch {
        return response.ok({ body: { enabled: config.liveness?.enabled, intervalSeconds: config.liveness?.intervalSeconds, checkedAt: null, nodes: {} } });
      }
    }
  );
}
