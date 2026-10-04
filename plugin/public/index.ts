import './index.scss';

import { VulnmapperPlugin } from './plugin';

// This exports static code and TypeScript types,
// as well as, OpenSearch Dashboards Platform `plugin()` initializer.
export function plugin() {
  return new VulnmapperPlugin();
}
export { VulnmapperPluginSetup, VulnmapperPluginStart } from './types';
