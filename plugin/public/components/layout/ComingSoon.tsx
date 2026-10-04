import React from 'react';
import { EuiButton, EuiEmptyPrompt, EuiPanel } from '@elastic/eui';
import { PageDef } from '../../pages';
import { useServices } from '../../lib/services';

// Route body for pages whose feature does not exist yet.
export function ComingSoon({ page }: { page: PageDef }) {
  const { history } = useServices();
  return (
    <EuiPanel paddingSize="l">
      <EuiEmptyPrompt
        iconType={page.icon}
        title={<h2>{page.title} is coming soon</h2>}
        body={<p>{page.description} This feature is not available yet.</p>}
        actions={
          <EuiButton onClick={() => history.push('/')} iconType="arrowLeft">
            Back to overview
          </EuiButton>
        }
      />
    </EuiPanel>
  );
}
