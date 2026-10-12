// Mark this asset as one to protect: the owner picks its FIPS 199 importance (or
// unmarks it). Saving runs the recompute on the server, then re-reads the paths.
import React, { useState } from 'react';
import {
  EuiBadge,
  EuiButtonEmpty,
  EuiButtonGroup,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiSpacer,
  EuiText,
} from '@elastic/eui';
import { Importance } from '../../../common';
import { useAttackPaths } from '../../lib/attackPathsData';
import { useServices } from '../../lib/services';
import { IMPORTANCE_LEVELS, IMPORTANCE_META, IMPORTANCE_SHORT } from '../../lib/attackPaths';
import { Section } from './DetailSections';

export function ProtectControl({ nodeId }: { nodeId: string }) {
  const { doc, reload } = useAttackPaths();
  const { http } = useServices();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const current = doc?.targets.find((t) => t.id === nodeId)?.importance ?? null;

  const save = async (importance: Importance | null) => {
    setBusy(true);
    setError(null);
    try {
      await http.post('/api/vulnmapper/targets', { body: JSON.stringify({ id: nodeId, importance }) });
      await reload();
    } catch (e) {
      setError(e.body?.message || e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section title="Protect this asset">
      <EuiText size="xs" color="subdued">
        <p>
          Mark this asset's importance (FIPS 199) to see the routes that could reach it on the
          Attack paths page.
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} wrap>
        <EuiFlexItem grow={false}>
          <EuiButtonGroup
            legend="Importance"
            isDisabled={busy}
            idSelected={current || ''}
            onChange={(id: string) => save(id as Importance)}
            options={IMPORTANCE_LEVELS.map((l) => ({
              id: l,
              label: IMPORTANCE_SHORT[l],
              'data-test-subj': `vmProtect-${l}`,
            }))}
            data-test-subj="vmProtect"
          />
        </EuiFlexItem>
        {current && (
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty size="s" iconType="cross" isDisabled={busy} onClick={() => save(null)} data-test-subj="vmUnprotect">
              Unmark
            </EuiButtonEmpty>
          </EuiFlexItem>
        )}
        {current && (
          <EuiFlexItem grow={false}>
            <EuiBadge color={IMPORTANCE_META[current].color}>{IMPORTANCE_META[current].label}</EuiBadge>
          </EuiFlexItem>
        )}
      </EuiFlexGroup>
      {error && (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut color="danger" size="s" iconType="alert" title={error} />
        </>
      )}
    </Section>
  );
}
