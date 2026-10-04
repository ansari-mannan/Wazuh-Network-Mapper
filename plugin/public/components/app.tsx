import React, { ComponentType, useEffect } from 'react';
import { I18nProvider } from '@osd/i18n/react';
import { Route, Router, Switch } from 'react-router-dom';

import { PLUGIN_NAME } from '../../common';
import { PageDef, PAGES } from '../pages';
import { GraphProvider } from '../lib/graph';
import { Services, ServicesProvider, useServices } from '../lib/services';
import { Overview } from './overview/Overview';
import { InnerPage } from './layout/InnerPage';
import { ComingSoon } from './layout/ComingSoon';
import { TopologyPage } from './topology/TopologyPage';
import { ScanSettingsPage } from './scan/ScanSettingsPage';

// Page bodies by page id. A page without an entry here (or not `available` in
// PAGES) renders the "coming soon" empty state.
const PAGE_COMPONENTS: Record<string, ComponentType> = {
  topology: TopologyPage,
  scan: ScanSettingsPage,
};

function useBreadcrumbs(page?: PageDef) {
  const { chrome, history } = useServices();
  useEffect(() => {
    const root = {
      text: PLUGIN_NAME,
      href: history.createHref({ pathname: '/' }),
      onClick: (e: React.MouseEvent) => {
        e.preventDefault();
        history.push('/');
      },
    };
    chrome.setBreadcrumbs(page ? [root, { text: page.title }] : [{ text: PLUGIN_NAME }]);
    chrome.docTitle.change(page ? [page.title, PLUGIN_NAME] : PLUGIN_NAME);
  }, [chrome, history, page]);
}

function OverviewRoute() {
  useBreadcrumbs();
  return <Overview />;
}

function PageRoute({ page }: { page: PageDef }) {
  useBreadcrumbs(page);
  const Body = page.available ? PAGE_COMPONENTS[page.id] : undefined;
  return <InnerPage page={page}>{Body ? <Body /> : <ComingSoon page={page} />}</InnerPage>;
}

export const VulnmapperApp = ({ services }: { services: Services }) => (
  <I18nProvider>
    <ServicesProvider value={services}>
      <GraphProvider>
        <Router history={services.history}>
          <Switch>
            {PAGES.map((page) => (
              <Route key={page.id} path={`/${page.id}`} exact>
                <PageRoute page={page} />
              </Route>
            ))}
            <Route>
              <OverviewRoute />
            </Route>
          </Switch>
        </Router>
      </GraphProvider>
    </ServicesProvider>
  </I18nProvider>
);
