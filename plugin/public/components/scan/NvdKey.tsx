// The NVD API key box: save, remove or test the key the server uses for NVD
// lookups. Only its status comes back from the server, never the key; a typed
// key lives in this component's state until it is saved or tested.
import React, { useCallback, useEffect, useState } from 'react';
import { EuiButton, EuiFieldPassword, EuiFlexGroup, EuiFlexItem, EuiFormRow, EuiPanel, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { useServices } from '../../lib/services';

export type NvdKeyState = { source: 'saved' | 'env' | 'none'; savedAt: string | null };
type TestResult = 'valid' | 'invalid' | 'unreachable';

const URL = '/api/vulnmapper/settings/nvd-key';

/** The status line, e.g. "Key set (saved here on 26/10/2026)". Pure. */
export function nvdKeyText(state: NvdKeyState): string {
  if (state.source === 'saved') {
    return state.savedAt ? `Key set (saved here on ${new Date(state.savedAt).toLocaleDateString()})` : 'Key set (saved here)';
  }
  return state.source === 'env' ? "Key from the server's environment" : 'No key (slower lookups)';
}

const TEST_TEXT: Record<TestResult, string> = {
  valid: 'NVD accepted the key.',
  invalid: 'NVD rejected the key.',
  unreachable: 'NVD did not answer; try again later.',
};

const errorText = (e: any) => e?.body?.message || e?.message || String(e);

export function NvdKey() {
  const { http, notifications } = useServices();
  const [state, setState] = useState<NvdKeyState | null>(null);
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [tested, setTested] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setState(await http.get<NvdKeyState>(URL));
    } catch {
      setState(null);
    }
  }, [http]);
  useEffect(() => {
    load();
  }, [load]);

  const act = async (what: string, call: () => Promise<void>) => {
    setBusy(true);
    setTested(null);
    try {
      await call();
    } catch (e) {
      notifications.toasts.addDanger({ title: `Could not ${what}`, text: errorText(e) });
    } finally {
      setBusy(false);
    }
  };
  const save = () =>
    act('save the NVD API key', async () => {
      setState(await http.post<NvdKeyState>(URL, { body: JSON.stringify({ key }) }));
      setKey('');
    });
  const remove = () => act('remove the NVD API key', async () => setState(await http.delete<NvdKeyState>(URL)));
  const test = () =>
    act('test the NVD API key', async () => {
      const { result } = await http.post<{ result: TestResult }>(`${URL}/test`, { body: JSON.stringify(key ? { key } : {}) });
      setTested(TEST_TEXT[result]);
    });

  return (
    <EuiPanel paddingSize="m" data-test-subj="vmNvdKey">
      <EuiTitle size="xs">
        <h2>NVD API key</h2>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiText size="s" data-test-subj="vmNvdKeyStatus">
        <p>{state ? nvdKeyText(state) : '—'}</p>
      </EuiText>
      <EuiSpacer size="s" />
      <EuiFormRow
        label="NVD API key"
        helpText="Get a free key at nvd.nist.gov/developers/request-an-api-key. Saved on the server, used for NVD lookups."
      >
        <EuiFieldPassword
          value={key}
          onChange={(e) => setKey(e.target.value)}
          autoComplete="off"
          data-test-subj="vmNvdKeyField"
        />
      </EuiFormRow>
      <EuiFlexGroup gutterSize="s" responsive={false} wrap>
        <EuiFlexItem grow={false}>
          <EuiButton size="s" fill onClick={save} isDisabled={busy || !key.trim()} data-test-subj="vmNvdKeySave">
            Save
          </EuiButton>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButton size="s" onClick={remove} isDisabled={busy || state?.source !== 'saved'} data-test-subj="vmNvdKeyRemove">
            Remove
          </EuiButton>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButton
            size="s"
            onClick={test}
            isDisabled={busy || (!key.trim() && (!state || state.source === 'none'))}
            data-test-subj="vmNvdKeyTest"
          >
            Test key
          </EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>
      {tested && (
        <EuiText size="s" data-test-subj="vmNvdKeyTested">
          <EuiSpacer size="s" />
          <p>{tested}</p>
        </EuiText>
      )}
    </EuiPanel>
  );
}
