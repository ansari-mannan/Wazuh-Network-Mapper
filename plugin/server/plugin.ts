// Registers the plugin's routes and starts the background liveness check and
// the scan schedule.
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
import { createScheduler, hasEnvCredential, Scheduler, scheduleFilePath } from './schedule';
import { startScan } from './scan';

// Scheduled scans run with every active check off (configuredChecks is not used).
const NO_ACTIVE_CHECKS = {
  checkDefaultCommunities: false,
  checkManagementPorts: false,
  probeUnmanagedSnmp: false,
  nmapUnmanaged: false,
};

export class VulnmapperPlugin implements Plugin<VulnmapperPluginSetup, VulnmapperPluginStart> {
  private readonly logger: Logger;
  private config: VulnmapperConfig | null = null;
  private scheduler: Scheduler | null = null;

  constructor(private readonly initializerContext: PluginInitializerContext) {
    this.logger = initializerContext.logger.get();
  }

  public async setup(core: CoreSetup) {
    this.logger.debug('vulnmapper: Setup');
    this.config = await this.initializerContext.config
      .create<VulnmapperConfig>()
      .pipe(first())
      .toPromise();
    const { backendDir, graphPath, pythonBin, deviceCves, seeds, scanTimeoutSeconds } = this.config;
    if (backendDir && graphPath) {
      const logger = this.logger;
      this.scheduler = createScheduler({
        file: scheduleFilePath(graphPath),
        // no community argument: the scanner reads the server environment
        startScan: (onDone) =>
          startScan({ pythonBin, backendDir, graphPath, deviceCves, seeds, timeoutSeconds: scanTimeoutSeconds, checks: NO_ACTIVE_CHECKS, trigger: 'scheduled', onDone, logger }),
        hasCredential: () => hasEnvCredential(process.env),
        logger,
      });
    }
    const router = core.http.createRouter();
    defineRoutes(router, this.config, this.logger, this.scheduler);
    return {};
  }

  public start(core: CoreStart) {
    this.logger.debug('vulnmapper: Started');
    if (this.config) startLiveness(this.config, this.logger);
    this.scheduler?.load().catch((e) => this.logger.warn(`could not load the scan schedule: ${e.message}`));
    return {};
  }

  public stop() {
    stopLiveness();
    this.scheduler?.stop();
  }
}
