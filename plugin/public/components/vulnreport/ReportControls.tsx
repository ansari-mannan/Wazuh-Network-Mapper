// The report's controls: mode, the staged filters, and PDF export. Screen
// only; the print stylesheet hides them from the PDF. The filters edit a
// draft that reaches the report on Apply (or Enter); the mode and the PDF cap
// are views and settings, and act at once.
import React from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiButtonGroup,
  EuiCheckboxGroup,
  EuiComboBox,
  EuiFieldNumber,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiPanel,
  EuiSelect,
  EuiSwitch,
  EuiText,
  EuiToolTip,
} from '@elastic/eui';
import { Severity, SEVERITIES } from '../../lib/report';
import { Confidence, StagedFilters } from '../../lib/reportFilters';
import { SEV_META } from './format';

export type ReportMode = 'ranked' | 'single';
export type { Confidence };

export const ON_PATH_HELP =
  'Only assets on a route to a protected asset. Mark protected assets on the map or the Attack paths page.';

interface Props {
  mode: ReportMode;
  onMode: (mode: ReportMode) => void;
  assetOptions: Array<{ label: string; value: string }>;
  /** the filters as edited, not yet applied */
  draft: StagedFilters;
  onDraft: (change: Partial<StagedFilters>) => void;
  /** the draft differs from what the report shows */
  dirty: boolean;
  onApply: () => void;
  onReset: () => void;
  /** whether any asset is marked protected (else "On an attack path" means nothing) */
  hasProtected: boolean;
  pdfCap: number;
  onPdfCap: (n: number) => void;
  onExport: () => void;
}

export function ReportControls(p: Props) {
  const { draft } = p;
  const severityCheckboxes = SEVERITIES.map((s) => ({ id: s, label: SEV_META[s].label }));
  const severitySelection = Object.fromEntries(SEVERITIES.map((s) => [s, draft.severities.includes(s)]));
  const toggleSeverity = (s: Severity) =>
    p.onDraft({ severities: draft.severities.includes(s) ? draft.severities.filter((x) => x !== s) : [...draft.severities, s] });
  // Enter in a field, list or checkbox applies the draft; a button (Apply,
  // Reset, the mode, the switch) does its own thing on Enter
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !(e.target as Element).closest('button')) {
      e.preventDefault();
      p.onApply();
    }
  };
  const onPathSwitch = (
    <EuiSwitch
      label="On an attack path"
      checked={draft.onPath}
      disabled={!p.hasProtected}
      onChange={(e) => p.onDraft({ onPath: e.target.checked })}
      data-test-subj="vmOnPathSwitch"
    />
  );
  return (
    <EuiPanel paddingSize="m" hasBorder className="vmReportControls vmScreenOnly" data-test-subj="vmReportControls">
      <div onKeyDown={onKeyDown}>
        <EuiFlexGroup gutterSize="m" alignItems="flexEnd" wrap>
          <EuiFlexItem grow={false}>
            <EuiFormRow label="Report mode">
              <EuiButtonGroup
                legend="Report mode"
                idSelected={p.mode}
                onChange={(id) => p.onMode(id as ReportMode)}
                options={[
                  { id: 'ranked', label: 'Most vulnerable assets' },
                  { id: 'single', label: 'Single asset' },
                ]}
              />
            </EuiFormRow>
          </EuiFlexItem>
          {p.mode === 'single' && (
            <EuiFlexItem style={{ minWidth: 260 }}>
              <EuiFormRow label="Asset">
                <EuiComboBox
                  singleSelection={{ asPlainText: true }}
                  options={p.assetOptions}
                  selectedOptions={p.assetOptions.filter((o) => o.value === draft.assetId)}
                  onChange={(sel) => p.onDraft({ assetId: sel[0]?.value ?? null })}
                  placeholder="Pick an asset"
                  isClearable={false}
                />
              </EuiFormRow>
            </EuiFlexItem>
          )}
          {p.mode === 'ranked' && (
            <EuiFlexItem grow={false}>
              <EuiFormRow label="Top N">
                <EuiFieldNumber
                  value={draft.topN}
                  min={1}
                  onChange={(e) => p.onDraft({ topN: Math.max(1, Number(e.target.value) || 1) })}
                  style={{ width: 90 }}
                  data-test-subj="vmTopN"
                />
              </EuiFormRow>
            </EuiFlexItem>
          )}
          <EuiFlexItem grow={false}>
            <EuiFormRow label="Confidence">
              <EuiSelect
                value={draft.confidence}
                onChange={(e) => p.onDraft({ confidence: e.target.value as Confidence })}
                options={[
                  { value: 'all', text: 'All' },
                  { value: 'confirmed', text: 'Confirmed only' },
                  { value: 'potential', text: 'Potential only' },
                ]}
                data-test-subj="vmConfidence"
              />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiFormRow label="Severity">
              <EuiCheckboxGroup
                options={severityCheckboxes}
                idToSelectedMap={severitySelection}
                onChange={(id) => toggleSeverity(id as Severity)}
                className="vmSeverityGroup"
              />
            </EuiFormRow>
          </EuiFlexItem>
          {/* with nothing protected there are no routes to filter by: disabled, the help as tooltip */}
          <EuiFlexItem grow={false} style={{ maxWidth: 280 }}>
            <EuiFormRow label="Attack paths" helpText={ON_PATH_HELP}>
              {p.hasProtected ? onPathSwitch : <EuiToolTip content={ON_PATH_HELP}>{onPathSwitch}</EuiToolTip>}
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiFormRow hasEmptyLabelSpace>
              <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    iconType="check"
                    onClick={p.onApply}
                    isDisabled={!p.dirty}
                    className={p.dirty ? 'vmApply vmApply--dirty' : 'vmApply'}
                    data-test-subj="vmApplyFilters"
                  >
                    Apply
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButtonEmpty size="s" onClick={p.onReset} data-test-subj="vmResetFilters">
                    Reset
                  </EuiButtonEmpty>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiFormRow label="Per-asset CVE cap (PDF)">
              <EuiFieldNumber value={p.pdfCap} min={1} onChange={(e) => p.onPdfCap(Math.max(1, Number(e.target.value) || 1))} style={{ width: 110 }} />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiFormRow hasEmptyLabelSpace>
              <EuiButton iconType="document" fill onClick={p.onExport} data-test-subj="vmExportPdf">
                Export PDF
              </EuiButton>
            </EuiFormRow>
          </EuiFlexItem>
        </EuiFlexGroup>
        {p.dirty && (
          <EuiText size="xs" color="warning" className="vmFiltersChanged" data-test-subj="vmFiltersChanged">
            <p>Filters changed: press Apply</p>
          </EuiText>
        )}
      </div>
    </EuiPanel>
  );
}
