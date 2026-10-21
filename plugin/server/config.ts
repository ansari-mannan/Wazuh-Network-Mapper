// The plugin's settings (vulnmapper.* in opensearch_dashboards.yml) and their defaults.
import { isIP } from 'net';
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
//   vulnmapper.nmapUnmanaged  the switch "Service-scan unmanaged hosts with
//                          nmap" (default false). On, a scan passes
//                          --nmap-unmanaged: nmap actively connects to and
//                          probes the discovered unmanaged hosts (open ports,
//                          service versions -> NVD CVEs), never managed hosts
//                          or network devices. nmap must be installed.
//   vulnmapper.scanTimeoutSeconds  a scan still running after this long is
//                          stopped and fails (default 1800, min 60)
//   vulnmapper.seeds       IP addresses the network crawl starts from, each
//                          passed as --seed (default none: the dashboard
//                          server's default gateway and LLDP neighbours)
//   vulnmapper.liveness.*  liveness: quick up/down checks of the nodes already
//     on the map every interval, shown on the map (off by default):
//     enabled, intervalSeconds (default 60, min 10), missThreshold (min 1),
//     agentMaxAgeSeconds (oldest Wazuh agent check-in that counts, default
//     30, min 10), and path (default: liveness.json in the same folder as
//     graphPath).
//     autoRescan (default false): also start a full scan when a liveness pass
//     sees something appear that is not on the map, at most every
//     minRescanIntervalSeconds (min 60)
//   vulnmapper.wazuhCard.*  the card for this plugin on the Wazuh Overview
//     page: enabled (default true) and section, the header of the Overview
//     section it is added to (default "THREAT INTELLIGENCE"; also e.g.
//     "ENDPOINT SECURITY", "SECURITY OPERATIONS"; case does not matter).
//     Both reach the browser (index.ts, exposeToBrowser).
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
  nmapUnmanaged: schema.boolean({ defaultValue: false }),
  scanTimeoutSeconds: schema.number({ defaultValue: 1800, min: 60 }),
  seeds: schema.arrayOf(
    schema.string({ validate: (v) => (isIP(v) ? undefined : `${v} is not an IP address`) }),
    { defaultValue: [] }
  ),
  // The organisation/owner name shown on the vulnerability report's cover.
  reportOrg: schema.string({ defaultValue: 'Network Vulnerability Assessment' }),
  liveness: schema.object({
    enabled: schema.boolean({ defaultValue: false }),
    // each pass starts a Python process (pysnmp, networkx, requests); every 10 s
    // was a noticeable load on the dashboard server
    intervalSeconds: schema.number({ defaultValue: 60, min: 10 }),
    missThreshold: schema.number({ defaultValue: 2, min: 1 }),
    agentMaxAgeSeconds: schema.number({ defaultValue: 30, min: 10 }),
    // off: a full scan is a much heavier thing than the up/down check (docs/DECISIONS.md, Q3)
    autoRescan: schema.boolean({ defaultValue: false }),
    minRescanIntervalSeconds: schema.number({ defaultValue: 120, min: 60 }),
    path: schema.maybe(schema.string()),
  }),
  wazuhCard: schema.object({
    enabled: schema.boolean({ defaultValue: true }),
    section: schema.string({ defaultValue: 'THREAT INTELLIGENCE', minLength: 1 }),
  }),
});

export type VulnmapperConfig = TypeOf<typeof configSchema>;

/** The active checks' configured defaults (all off unless the owner turns them on). */
export function configuredChecks(config: VulnmapperConfig): ActiveChecks {
  const { checkDefaultCommunities, checkManagementPorts, probeUnmanagedSnmp, nmapUnmanaged } = config;
  return { checkDefaultCommunities, checkManagementPorts, probeUnmanagedSnmp, nmapUnmanaged };
}
