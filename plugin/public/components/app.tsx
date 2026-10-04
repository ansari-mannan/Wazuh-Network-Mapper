import React, { useEffect, useState } from 'react';
import { I18nProvider } from '@osd/i18n/react';
import { BrowserRouter as Router } from 'react-router-dom';
import {
  EuiCallOut,
  EuiLoadingSpinner,
  EuiPage,
  EuiPageBody,
  EuiPageHeader,
  EuiPanel,
  EuiText,
  EuiTitle,
} from '@elastic/eui';

import { CoreStart } from '../../../../src/core/public';
import { GraphResponse, PLUGIN_NAME } from '../../common';
import { TopologyView } from './topology/TopologyView';

interface VulnmapperAppDeps {
  basename: string;
  http: CoreStart['http'];
}

// PHASE 1 SPIKE: a single page that loads the graph and draws it.
export const VulnmapperApp = ({ basename, http }: VulnmapperAppDeps) => {
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    http
      .get<GraphResponse>('/api/vulnmapper/graph')
      .then(setGraph)
      .catch((e) => setError(e.body?.message || e.message));
  }, [http]);

  return (
    <Router basename={basename}>
      <I18nProvider>
        <EuiPage>
          <EuiPageBody component="main">
            <EuiPageHeader>
              <EuiTitle size="l">
                <h1>{PLUGIN_NAME}</h1>
              </EuiTitle>
            </EuiPageHeader>
            {error && <EuiCallOut color="danger" title={error} iconType="alert" />}
            {!graph && !error && <EuiLoadingSpinner size="xl" />}
            {graph && (
              <>
                <EuiText size="s" data-test-subj="vmCounts">
                  <p>
                    {graph.nodes.length} nodes · {graph.edges.length} links
                    {selected ? ` · selected ${selected}` : ''}
                  </p>
                </EuiText>
                <EuiPanel paddingSize="none" className="vmTopology" style={{ height: '70vh' }}>
                  <TopologyView graph={graph} onSelect={setSelected} />
                </EuiPanel>
              </>
            )}
          </EuiPageBody>
        </EuiPage>
      </I18nProvider>
    </Router>
  );
};
