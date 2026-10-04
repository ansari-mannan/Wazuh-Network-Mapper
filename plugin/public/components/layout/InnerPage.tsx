import React, { ReactNode } from 'react';
import { EuiButtonEmpty, EuiPage, EuiPageBody, EuiPageHeader, EuiSpacer } from '@elastic/eui';
import { PageDef, PAGES } from '../../pages';
import { useServices } from '../../lib/services';

interface InnerPageProps {
  page: PageDef;
  children: ReactNode;
  /** extra controls on the right of the title */
  rightSideItems?: ReactNode[];
  className?: string;
}

// Shell of every page except the overview: a link back to the overview, the
// page title and a tab row with every page (unavailable ones disabled).
export function InnerPage({ page, children, rightSideItems, className }: InnerPageProps) {
  const { history } = useServices();
  return (
    <EuiPage className={`vmInnerPage ${className || ''}`}>
      <EuiPageBody component="main">
        <div>
          <EuiButtonEmpty
            iconType="arrowLeft"
            size="xs"
            flush="left"
            onClick={() => history.push('/')}
            data-test-subj="vmBackToOverview"
          >
            Overview
          </EuiButtonEmpty>
        </div>
        <EuiPageHeader
          pageTitle={page.title}
          rightSideItems={rightSideItems}
          tabs={PAGES.map((p) => ({
            label: p.title,
            isSelected: p.id === page.id,
            disabled: !p.available,
            onClick: () => history.push(`/${p.id}`),
            'data-test-subj': `vmTab-${p.id}`,
          }))}
        />
        <EuiSpacer size="m" />
        {children}
      </EuiPageBody>
    </EuiPage>
  );
}
