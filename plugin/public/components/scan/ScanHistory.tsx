// The last 10 successful scans (manual, scheduled or automatic) with their key
// counts; the selected one shows what changed since the scan before it and
// its stage table.
import React, { useMemo, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiCallOut,
  EuiDescriptionList,
  EuiLoadingContent,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { HistoryEntry, ScanTrigger } from '../../../common';
import { useHistoryChanges, useHistoryIndex } from '../../lib/history';
import { ChangedAsset, CveChange, scanChanges } from '../../lib/scanChanges';
import { useServices } from '../../lib/services';
import { NODE_LEVEL_META } from '../../lib/risk';
import { ScanStages } from './GraphSource';
import { formatTime } from './ScanStatus';

const TRIGGER_WORDS: Record<ScanTrigger, string> = { manual: 'Manual', scheduled: 'Scheduled', automatic: 'Automatic' };

const countsText = ({ counts: c }: HistoryEntry) =>
  `${c.devices} devices · ${c.endpoints} hosts · ${c.cvesConfirmed} confirmed + ${c.cvesPotential} potential CVEs · ${c.configFindings} config findings`;

const names = (list: ChangedAsset[]) => list.map((a) => a.name).join(', ');
const cveLines = (list: CveChange[]) => list.map((c) => `${c.asset.name}: ${c.cves.join(', ')}`);

function Changes({ id }: { id: string }) {
  const { data, error } = useHistoryChanges(id);
  const changes = useMemo(() => (data?.previous ? scanChanges(data.previous, data.current) : null), [data]);
  if (error) return <EuiCallOut size="s" color="danger" iconType="alert" title={error} />;
  if (!data) return <EuiLoadingContent lines={3} />;
  if (!changes) {
    return (
      <EuiText size="s" color="subdued" data-test-subj="vmHistoryFirst">
        <p>The oldest scan in the history: there is no earlier scan to compare it with.</p>
      </EuiText>
    );
  }
  const rows: Array<{ title: string; description: React.ReactElement[] }> = [];
  const add = (title: string, lines: string[]) => {
    if (lines.length) rows.push({ title, description: lines.map((l) => <div key={l}>{l}</div>) });
  };
  add('Added', changes.added.length ? [names(changes.added)] : []);
  add('Removed', changes.removed.length ? [names(changes.removed)] : []);
  add('Went offline', changes.wentOffline.length ? [names(changes.wentOffline)] : []);
  add('Back online', changes.backOnline.length ? [names(changes.backOnline)] : []);
  add('New CVEs', cveLines(changes.newCves || []));
  add('No longer present', cveLines(changes.goneCves || []));
  add(
    'Risk changed',
    changes.riskChanged.map((r) => `${r.asset.name}: ${NODE_LEVEL_META[r.from].label} → ${NODE_LEVEL_META[r.to].label}`)
  );
  return (
    <>
      <EuiText size="xs" color="subdued">
        <p>
          Compared with the scan of {formatTime(data.previous!.entry.time)}.
          {changes.newCves === null && ' One of the two has no vulnerabilities file, so CVEs are not compared.'}
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      {rows.length ? (
        <EuiDescriptionList compressed type="column" listItems={rows} data-test-subj="vmHistoryChanges" />
      ) : (
        <EuiText size="s" data-test-subj="vmHistoryNoChanges">
          <p>Nothing changed.</p>
        </EuiText>
      )}
    </>
  );
}

export function ScanHistory() {
  const { history } = useServices();
  const { index, error } = useHistoryIndex();
  // ?history=<id> (the overview's link) selects a scan; else the newest
  const [picked, setPicked] = useState<string | null>(
    () => new URLSearchParams(history?.location?.search || '').get('history')
  );
  const selected = index?.find((e) => e.id === picked) || index?.[0] || null;

  return (
    <EuiPanel paddingSize="m" data-test-subj="vmScanHistory">
      <EuiTitle size="xs">
        <h2>Scan history</h2>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiText size="xs" color="subdued">
        <p>The last 10 successful scans. Select one to see what changed since the scan before it.</p>
      </EuiText>
      <EuiSpacer size="m" />
      {error && <EuiCallOut size="s" color="danger" iconType="alert" title={error} />}
      {index && !index.length && (
        <EuiText size="s" color="subdued">
          <p>No scan has been recorded yet; each successful scan is added here.</p>
        </EuiText>
      )}
      {index && index.length > 0 && (
        <>
          <EuiBasicTable<HistoryEntry>
            compressed
            items={index}
            itemId="id"
            data-test-subj="vmHistoryList"
            rowProps={(e) => ({
              onClick: () => setPicked(e.id),
              isSelected: e.id === selected?.id,
              style: { cursor: 'pointer' },
              'data-test-subj': `vmHistoryRow-${e.id}`,
            })}
            columns={[
              { field: 'time', name: 'Finished', width: '190px', render: (t: string) => formatTime(t) },
              {
                field: 'trigger',
                name: 'Started by',
                width: '100px',
                render: (t: ScanTrigger) => <EuiBadge color="hollow">{TRIGGER_WORDS[t] || t}</EuiBadge>,
              },
              { field: 'counts', name: 'Found', render: (_: unknown, e: HistoryEntry) => countsText(e) },
            ]}
          />
          {selected && (
            <>
              <EuiSpacer size="l" />
              <EuiTitle size="xxs">
                <h3>What changed in the scan of {formatTime(selected.time)}</h3>
              </EuiTitle>
              <EuiSpacer size="s" />
              <Changes id={selected.id} />
              {selected.stages.length > 0 && <ScanStages stages={selected.stages} title="That scan, stage by stage" />}
            </>
          )}
        </>
      )}
    </EuiPanel>
  );
}
