import React from 'react';
import {
  EuiCallOut,
  EuiButton,
  EuiCard,
  EuiFlexGrid,
  EuiFlexGroup,
  EuiFlexItem,
  EuiIcon,
  EuiLoadingContent,
  EuiPage,
  EuiPageBody,
  EuiPageHeader,
  EuiPanel,
  EuiSpacer,
  EuiTitle,
} from '@elastic/eui';
import { PLUGIN_NAME } from '../../../common';
import { PAGE_GROUPS, PAGES } from '../../pages';
import { useGraph } from '../../lib/graph';
import { useServices } from '../../lib/services';
import { SummaryPanels } from './SummaryPanels';

function PageCards() {
  const { history } = useServices();
  return (
    <EuiFlexGroup gutterSize="m">
      {PAGE_GROUPS.map((group) => {
        const pages = PAGES.filter((p) => p.group === group.id);
        return (
          <EuiFlexItem key={group.id} grow={pages.length as 2 | 3}>
            <EuiPanel paddingSize="m">
              <EuiTitle size="xs">
                <h2>{group.title}</h2>
              </EuiTitle>
              <EuiSpacer size="m" />
              <EuiFlexGrid columns={pages.length as 2 | 3} gutterSize="m">
                {pages.map((page) => (
                  <EuiFlexItem key={page.id}>
                    <EuiCard
                      layout="horizontal"
                      icon={<EuiIcon type={page.icon} size="xl" />}
                      title={page.title}
                      titleSize="xs"
                      description={page.description}
                      isDisabled={!page.available}
                      betaBadgeProps={page.available ? undefined : { label: 'Coming soon' }}
                      onClick={page.available ? () => history.push(`/${page.id}`) : undefined}
                      data-test-subj={`vmCard-${page.id}`}
                    />
                  </EuiFlexItem>
                ))}
              </EuiFlexGrid>
            </EuiPanel>
          </EuiFlexItem>
        );
      })}
    </EuiFlexGroup>
  );
}

export function Overview() {
  const { graph, loading, error, reload } = useGraph();
  return (
    <EuiPage>
      <EuiPageBody component="main">
        <EuiPageHeader pageTitle={PLUGIN_NAME} />
        <EuiSpacer size="m" />
        {error && (
          <>
            <EuiCallOut color="danger" iconType="alert" title="Could not load the graph">
              <p>{error}</p>
              <EuiButton size="s" color="danger" onClick={reload}>
                Retry
              </EuiButton>
            </EuiCallOut>
            <EuiSpacer size="m" />
          </>
        )}
        {graph ? (
          <SummaryPanels graph={graph} />
        ) : (
          loading && <EuiLoadingContent lines={5} />
        )}
        <EuiSpacer size="m" />
        <PageCards />
      </EuiPageBody>
    </EuiPage>
  );
}
