import { schema, TypeOf } from '@osd/config-schema';

// Plugin config, read from opensearch_dashboards.yml (or the dev config):
//   vulnmapper.backendDir  folder containing the Python `vulnmapper` package
//   vulnmapper.graphPath   graph.json written by a scan and served to the UI
//   vulnmapper.pythonBin   Python interpreter used to run the scanner
export const configSchema = schema.object({
  backendDir: schema.maybe(schema.string()),
  graphPath: schema.maybe(schema.string()),
  pythonBin: schema.string({ defaultValue: 'python3' }),
  liveness: schema.object({
    enabled: schema.boolean({ defaultValue: false }),
    intervalSeconds: schema.number({ defaultValue: 20 }),
    missThreshold: schema.number({ defaultValue: 3 }),
    path: schema.maybe(schema.string()),
  }, { defaultValue: {} }),
});

export type VulnmapperConfig = TypeOf<typeof configSchema>;
