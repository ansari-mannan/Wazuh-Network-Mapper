// The browser side's entry point, which the dashboard calls to create the plugin.
import './index.scss';

import { PluginInitializerContext } from '../../../src/core/public';
import { VulnmapperPlugin } from './plugin';

export function plugin(initializerContext: PluginInitializerContext) {
  return new VulnmapperPlugin(initializerContext);
}
export { VulnmapperPluginSetup, VulnmapperPluginStart } from './types';
