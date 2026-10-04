import { AppMountParameters, CoreSetup, CoreStart, Plugin } from '../../../src/core/public';
import { VulnmapperPluginSetup, VulnmapperPluginStart } from './types';
import { PLUGIN_ID, PLUGIN_NAME } from '../common';

export class VulnmapperPlugin implements Plugin<VulnmapperPluginSetup, VulnmapperPluginStart> {
  public setup(core: CoreSetup): VulnmapperPluginSetup {
    // Register an application into the side navigation menu
    core.application.register({
      id: PLUGIN_ID,
      title: PLUGIN_NAME,
      async mount(params: AppMountParameters) {
        // Load application bundle
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
