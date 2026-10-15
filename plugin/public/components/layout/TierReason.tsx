// Why a node has its tier (lib/ovssText tierReason): the rule as the tier
// badge's tooltip, and one short line under it.
import React, { ReactElement } from 'react';
import { EuiText, EuiToolTip } from '@elastic/eui';
import { TierReason } from '../../lib/ovssText';

export function TierTip({ why, children }: { why: TierReason | null; children: ReactElement }) {
  return why ? <EuiToolTip content={why.rule}>{children}</EuiToolTip> : children;
}

export function TierReasonLine({ why }: { why: TierReason | null }) {
  if (!why) return null;
  return (
    <EuiText size="xs" color="subdued" data-test-subj="vmTierReason">
      <p>{why.line}</p>
    </EuiText>
  );
}
