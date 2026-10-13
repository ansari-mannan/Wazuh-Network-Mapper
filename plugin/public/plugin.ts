// Registers the app with the dashboard; the app itself is mounted by
// application.tsx.
import { AppMountParameters, CoreSetup, CoreStart, Plugin } from '../../../src/core/public';
import { VulnmapperPluginSetup, VulnmapperPluginStart } from './types';
import { PLUGIN_ID, PLUGIN_NAME } from '../common';

export class VulnmapperPlugin implements Plugin<VulnmapperPluginSetup, VulnmapperPluginStart> {
  public setup(core: CoreSetup): VulnmapperPluginSetup {
    core.application.register({
      id: PLUGIN_ID,
      title: PLUGIN_NAME,
      async mount(params: AppMountParameters) {
        const { renderApp } = await import('./application');
        const [coreStart] = await core.getStartServices();
        return renderApp(coreStart, params);
      },
    });

    return {};
  }

  public start(core: CoreStart): VulnmapperPluginStart {
    return {};
  }

  public stop() {}
}
