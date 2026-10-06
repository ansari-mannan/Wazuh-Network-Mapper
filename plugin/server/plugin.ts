import { first } from 'rxjs/operators';
import {
  PluginInitializerContext,
  CoreSetup,
  CoreStart,
  Plugin,
  Logger,
} from '../../../src/core/server';

import { VulnmapperConfig } from './config';
import { VulnmapperPluginSetup, VulnmapperPluginStart } from './types';
import { defineRoutes } from './routes';
import { startLiveness, stopLiveness } from './liveness';

export class VulnmapperPlugin implements Plugin<VulnmapperPluginSetup, VulnmapperPluginStart> {
  private readonly logger: Logger;
  private config: VulnmapperConfig | null = null;

  constructor(private readonly initializerContext: PluginInitializerContext) {
    this.logger = initializerContext.logger.get();
  }

  public async setup(core: CoreSetup) {
    this.logger.debug('vulnmapper: Setup');
    this.config = await this.initializerContext.config
      .create<VulnmapperConfig>()
      .pipe(first())
      .toPromise();
    const router = core.http.createRouter();
    defineRoutes(router, this.config, this.logger);
    return {};
  }

  public start(core: CoreStart) {
    this.logger.debug('vulnmapper: Started');
    if (this.config) startLiveness(this.config, this.logger);
    return {};
  }

  public stop() {
    stopLiveness();
  }
}
