// The ONE list of plugin pages. It drives the overview cards, the tab row on
// inner pages and the routes; enabling a page later is flipping `available`.
export type PageGroup = 'network' | 'risk';

export interface PageDef {
  id: string;
  title: string;
  description: string;
  /** OUI icon type */
  icon: string;
  group: PageGroup;
  available: boolean;
}

export const PAGE_GROUPS: Array<{ id: PageGroup; title: string }> = [
  { id: 'network', title: 'Network' },
  { id: 'risk', title: 'Risk analysis' },
];

export const PAGES: PageDef[] = [
  {
    id: 'topology',
    title: 'Topology map',
    description: 'Interactive map of discovered devices, endpoints and links.',
    icon: 'graphApp',
    group: 'network',
    available: true,
  },
  {
    id: 'scan',
    title: 'Scan settings',
    description: 'Run a network scan and see where the current graph came from.',
    icon: 'gear',
    group: 'network',
    available: true,
  },
  {
    id: 'vulnerabilities',
    title: 'Vulnerabilities',
    description: 'CVEs found on endpoints, by severity and host.',
    icon: 'securitySignalDetected',
    group: 'risk',
    available: false,
  },
  {
    id: 'attack-paths',
    title: 'Attack paths',
    description: 'Routes an attacker could take from exposed hosts across the network.',
    icon: 'branch',
    group: 'risk',
    available: true,
  },
  {
    id: 'recommendations',
    title: 'Recommendations',
    description: 'Prioritised fixes to reduce network risk.',
    icon: 'bullseye',
    group: 'risk',
    available: false,
  },
];
