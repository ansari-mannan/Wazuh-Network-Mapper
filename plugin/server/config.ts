import { schema, TypeOf } from '@osd/config-schema';

// Plugin config, read from opensearch_dashboards.yml (or the dev config):
//   vulnmapper.backendDir  folder containing the Python `vulnmapper` package
//   vulnmapper.graphPath   graph.json written by a scan and served to the UI
//   vulnmapper.pythonBin   Python interpreter used to run the scanner
//   vulnmapper.deviceCves  look network devices' software up in NVD during a
//                          scan (default true; false passes --no-device-cves)
//   vulnmapper.liveness.*  the background liveness check (off by default):
//     enabled, intervalSeconds (min 10), missThreshold (min 1),
//     agentMaxAgeSeconds (oldest Wazuh agent check-in that counts, default
//     30, min 10),
//     autoRescan (start a scan when a pass sees something new) with
//     minRescanIntervalSeconds (min 60), and path (default: liveness.json in
//     the same folder as graphPath)
// backendDir and graphPath have no sensible default, so they are optional here
// and the routes answer with a clear error until they are set.
export const configSchema = schema.object({
  backendDir: schema.maybe(schema.string()),
  graphPath: schema.maybe(schema.string()),
  pythonBin: schema.string({ defaultValue: 'python3' }),
  deviceCves: schema.boolean({ defaultValue: true }),
  liveness: schema.object({
    enabled: schema.boolean({ defaultValue: false }),
    intervalSeconds: schema.number({ defaultValue: 10, min: 10 }),
    missThreshold: schema.number({ defaultValue: 2, min: 1 }),
    agentMaxAgeSeconds: schema.number({ defaultValue: 30, min: 10 }),
    autoRescan: schema.boolean({ defaultValue: true }),
    minRescanIntervalSeconds: schema.number({ defaultValue: 120, min: 60 }),
    path: schema.maybe(schema.string()),
  }),
});

export type VulnmapperConfig = TypeOf<typeof configSchema>;
