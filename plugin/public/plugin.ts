// Registers the app with the dashboard; the app itself is mounted by
// application.tsx. Also points at it from Wazuh's Overview page
// (wazuhCard.ts) and from the dashboard's home page, when there is one.
import { Subscription } from 'rxjs';
import {
  AppMountParameters,
  CoreSetup,
  CoreStart,
  DEFAULT_APP_CATEGORIES,
  Plugin,
  PluginInitializerContext,
} from '../../../src/core/public';
// types only, from the registry itself: home's public index pulls in the data
// plugin, whose generated SQL parser this TypeScript cannot read
import type {
  FeatureCatalogueCategory,
  FeatureCatalogueRegistrySetup,
} from '../../../src/plugins/home/public/services/feature_catalogue/feature_catalogue_registry';
import { VulnmapperPluginSetup, VulnmapperPluginStart } from './types';
import { PLUGIN_ID, PLUGIN_NAME } from '../common';
import { CARD_DESCRIPTION, watchWazuhOverview, WazuhCardConfig } from './wazuhCard';

export class VulnmapperPlugin implements Plugin<VulnmapperPluginSetup, VulnmapperPluginStart> {
  private wazuhCard?: Subscription;

  constructor(private readonly initializerContext: PluginInitializerContext) {}

  public setup(core: CoreSetup, { home }: { home?: { featureCatalogue: FeatureCatalogueRegistrySetup } }): VulnmapperPluginSetup {
    core.application.register({
      id: PLUGIN_ID,
      title: PLUGIN_NAME,
      category: DEFAULT_APP_CATEGORIES.security,
      async mount(params: AppMountParameters) {
        const { renderApp } = await import('./application');
        const [coreStart] = await core.getStartServices();
        return renderApp(coreStart, params);
      },
    });

    home?.featureCatalogue.register({
      id: PLUGIN_ID,
      title: PLUGIN_NAME,
      description: CARD_DESCRIPTION,
      icon: 'graphApp',
      path: `/app/${PLUGIN_ID}`,
      showOnHomePage: true,
      category: 'data' as FeatureCatalogueCategory,
    });

    return {};
  }

  public start(core: CoreStart): VulnmapperPluginStart {
    const { wazuhCard } = this.initializerContext.config.get<{ wazuhCard: WazuhCardConfig }>();
    this.wazuhCard = watchWazuhOverview(core.application.currentAppId$, core.application, wazuhCard);
    return {};
  }

  public stop() {
    this.wazuhCard?.unsubscribe();
  }
}
