import { promises as fs } from 'fs';
import { IRouter } from '../../../../src/core/server';

// PHASE 1 SPIKE ONLY: temporary hardcoded dev path. Replaced by the
// vulnmapper.graphPath config key in Phase 2.
const GRAPH_PATH = '/home/ans/dev/Wazuh-Network-Mapper/data/graph.json';

export function defineRoutes(router: IRouter) {
  // The graph is read fresh from disk on every request so the file the scanner
  // writes stays the single source of truth (same as frontend/app/api/graph).
  router.get(
    {
      path: '/api/vulnmapper/graph',
      validate: false,
    },
    async (context, request, response) => {
      let data: string;
      try {
        data = await fs.readFile(GRAPH_PATH, 'utf-8');
      } catch (err) {
        return response.notFound({
          body: { message: `Could not read graph at ${GRAPH_PATH}: ${(err as Error).message}` },
        });
      }
      try {
        return response.ok({ body: JSON.parse(data) });
      } catch (err) {
        return response.customError({
          statusCode: 500,
          body: { message: `graph.json is not valid JSON: ${(err as Error).message}` },
        });
      }
    }
  );
}
