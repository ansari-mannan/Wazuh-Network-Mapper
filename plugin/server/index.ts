import { PluginInitializerContext } from '../../../src/core/server';
import { VulnmapperPlugin } from './plugin';

// This exports static code and TypeScript types,
// as well as, OpenSearch Dashboards Platform `plugin()` initializer.

export function plugin(initializerContext: PluginInitializerContext) {
  return new VulnmapperPlugin(initializerContext);
}

export { VulnmapperPluginSetup, VulnmapperPluginStart } from './types';
