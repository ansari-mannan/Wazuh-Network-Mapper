import { schema, TypeOf } from '@osd/config-schema';
import { ActiveChecks } from '../common';

// Plugin config, read from opensearch_dashboards.yml (or the dev config):
//   vulnmapper.backendDir  folder containing the Python `vulnmapper` package
//   vulnmapper.graphPath   graph.json written by a scan and served to the UI
//   vulnmapper.pythonBin   Python interpreter used to run the scanner
//   vulnmapper.deviceCves  look network devices' software up in NVD during a
//                          scan (default true; false passes --no-device-cves)
//   vulnmapper.checkDefaultCommunities  the scan form's switch "Also test
//                          factory-default SNMP names (public, private)" starts
//                          in this position (default false). On, a scan passes
//                          --check-default-communities: two read-only SNMP
//                          requests per device, which the network may log as
//                          failed logins. The form's choice wins per scan.
//   vulnmapper.checkManagementPorts  the switch "Test whether telnet and web
//                          management answer on devices that do not report
//                          it" (default false). On, a scan passes
//                          --check-management-ports: one TCP connection to
//                          ports 23 and 80 of such a device, closed at once.
//   vulnmapper.probeUnmanagedSnmp  the switch "Ask unmanaged hosts for their
//                          identity over SNMP" (default false). On, a scan
//                          passes --probe-unmanaged-snmp: the scan's SNMP
//                          credential goes to hosts nobody has verified.
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
  checkDefaultCommunities: schema.boolean({ defaultValue: false }),
  checkManagementPorts: schema.boolean({ defaultValue: false }),
  probeUnmanagedSnmp: schema.boolean({ defaultValue: false }),
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

/** The active checks' configured defaults (all off unless the owner turns them on). */
export function configuredChecks(config: VulnmapperConfig): ActiveChecks {
  const { checkDefaultCommunities, checkManagementPorts, probeUnmanagedSnmp } = config;
  return { checkDefaultCommunities, checkManagementPorts, probeUnmanagedSnmp };
}
