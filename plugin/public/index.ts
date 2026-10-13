// The browser side's entry point, which the dashboard calls to create the plugin.
import './index.scss';

import { VulnmapperPlugin } from './plugin';

export function plugin() {
  return new VulnmapperPlugin();
}
export { VulnmapperPluginSetup, VulnmapperPluginStart } from './types';
