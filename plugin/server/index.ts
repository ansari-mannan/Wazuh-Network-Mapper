import { PluginConfigDescriptor, PluginInitializerContext } from '../../../src/core/server';
import { configSchema, VulnmapperConfig } from './config';
import { VulnmapperPlugin } from './plugin';

export const config: PluginConfigDescriptor<VulnmapperConfig> = {
  schema: configSchema,
};

export function plugin(initializerContext: PluginInitializerContext) {
  return new VulnmapperPlugin(initializerContext);
}

export { VulnmapperPluginSetup, VulnmapperPluginStart } from './types';
