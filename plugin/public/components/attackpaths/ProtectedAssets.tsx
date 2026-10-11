import React, { useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiButtonGroup,
  EuiCallOut,
  EuiComboBox,
  EuiComboBoxOptionOption,
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { GraphResponse, Importance } from '../../../common';
import { useAttackPaths } from '../../lib/attackPathsData';
import { useGraph } from '../../lib/graph';
import { useServices } from '../../lib/services';
import { IMPORTANCE_LEVELS, IMPORTANCE_SHORT } from '../../lib/attackPaths';

// A discoverable second entry to the same action as the Topology panel's "Protect
// this asset": it lists the marked targets and lets the owner add, re-rank or
// remove one. Reuses POST /api/vulnmapper/targets and the attack-paths provider
// (which reloads the computed routes after the server recompute); no new server logic.

function ImportanceButtons({
  idSelected,
  disabled,
  onChange,
  legend,
}: {
  idSelected: string;
  disabled: boolean;
  onChange: (importance: Importance) => void;
  legend: string;
}) {
  return (
    <EuiButtonGroup
      buttonSize="compressed"
      legend={legend}
      isDisabled={disabled}
      idSelected={idSelected}
      onChange={(id: string) => onChange(id as Importance)}
      options={IMPORTANCE_LEVELS.map((l) => ({ id: l, label: IMPORTANCE_SHORT[l] }))}
    />
  );
}

export function ProtectedAssets() {
  const { doc, reload } = useAttackPaths();
  const { graph } = useGraph();
  const { http } = useServices();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pick, setPick] = useState<Array<EuiComboBoxOptionOption<string>>>([]);
  const [addImportance, setAddImportance] = useState<Importance>('moderate');

  const targets = doc?.targets ?? [];
  const nameOf = (id: string) => {
    const n = (graph as GraphResponse | null)?.nodes.find((x) => x.node_id === id);
    return (n && (n.hostname || n.ip)) || id;
  };

  const save = async (id: string, importance: Importance | null) => {
    setBusy(true);
    setError(null);
    try {
      await http.post('/api/vulnmapper/targets', { body: JSON.stringify({ id, importance }) });
      await reload();
    } catch (e) {
      setError(e.body?.message || e.message);
    } finally {
      setBusy(false);
    }
  };

  // Scanned assets (devices and hosts) not already protected, for the picker.
  const targeted = new Set(targets.map((t) => t.id));
  const options: Array<EuiComboBoxOptionOption<string>> = (graph?.nodes ?? [])
    .filter((n) => !targeted.has(n.node_id))
    .map((n) => ({ label: n.hostname || n.ip || n.node_id, value: n.node_id }));

  const add = async () => {
    const id = pick[0]?.value;
    if (!id) return;
    await save(id, addImportance);
    setPick([]);
  };

  return (
    <EuiPanel paddingSize="m" hasBorder data-test-subj="vmProtectedAssets">
      <EuiTitle size="xs">
        <h3>Protected assets</h3>
      </EuiTitle>
      <EuiSpacer size="s" />

      {targets.length === 0 ? (
        <EuiText size="s" color="subdued">
          <p>
            No assets are marked to protect yet. Add one below (or from a node&apos;s panel on the
            Topology map) to see the routes that could reach it.
          </p>
        </EuiText>
      ) : (
        targets.map((t) => (
          <EuiFlexGroup
            key={t.id}
            gutterSize="s"
            alignItems="center"
            responsive={false}
            wrap
            className="vmProtectedRow"
            data-test-subj="vmProtectedAsset"
          >
            <EuiFlexItem style={{ minWidth: 0 }}>
              <EuiText size="s" className="vmTruncate">
                <strong>{t.label || nameOf(t.id)}</strong>
              </EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <ImportanceButtons
                legend={`Importance of ${t.label || nameOf(t.id)}`}
                idSelected={t.importance}
                disabled={busy}
                onChange={(importance) => save(t.id, importance)}
              />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButtonEmpty
                size="s"
                iconType="cross"
                isDisabled={busy}
                onClick={() => save(t.id, null)}
                data-test-subj="vmProtectedRemove"
              >
                Remove
              </EuiButtonEmpty>
            </EuiFlexItem>
          </EuiFlexGroup>
        ))
      )}

      <EuiSpacer size="m" />
      <EuiFlexGroup gutterSize="s" alignItems="flexEnd" responsive={false} wrap>
        <EuiFlexItem style={{ minWidth: 180 }}>
          <EuiComboBox
            placeholder="Add an asset to protect"
            singleSelection={{ asPlainText: true }}
            options={options}
            selectedOptions={pick}
            onChange={setPick}
            isDisabled={busy || !graph}
            isClearable
            data-test-subj="vmProtectAddPick"
          />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <ImportanceButtons
            legend="Importance for the new asset"
            idSelected={addImportance}
            disabled={busy}
            onChange={setAddImportance}
          />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButton size="s" onClick={add} isDisabled={busy || pick.length === 0} data-test-subj="vmProtectAdd">
            Add
          </EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>
      {error && (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut color="danger" size="s" iconType="alert" title={error} data-test-subj="vmProtectError" />
        </>
      )}
    </EuiPanel>
  );
}
