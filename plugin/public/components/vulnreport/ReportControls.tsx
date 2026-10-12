// The report's controls: mode, asset, filters and PDF export. Screen only;
// the print stylesheet hides them from the PDF.
import React from 'react';
import {
  EuiButton,
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
} from '@elastic/eui';
import { Severity, SEVERITIES } from '../../lib/report';
import { SEV_META } from './format';

export type ReportMode = 'ranked' | 'single';
export type Confidence = 'all' | 'confirmed' | 'potential';

interface Props {
  mode: ReportMode;
  onMode: (mode: ReportMode) => void;
  assetOptions: Array<{ label: string; value: string }>;
  assetId: string | null;
  onAsset: (id: string | null) => void;
  topN: number;
  onTopN: (n: number) => void;
  confidence: Confidence;
  onConfidence: (c: Confidence) => void;
  severities: Severity[];
  onToggleSeverity: (s: Severity) => void;
  pdfCap: number;
  onPdfCap: (n: number) => void;
  onPath: boolean;
  onOnPath: (on: boolean) => void;
  onExport: () => void;
}

export function ReportControls(p: Props) {
  const severityCheckboxes = SEVERITIES.map((s) => ({ id: s, label: SEV_META[s].label }));
  const severitySelection = Object.fromEntries(SEVERITIES.map((s) => [s, p.severities.includes(s)]));
  return (
    <EuiPanel paddingSize="m" hasBorder className="vmReportControls vmScreenOnly" data-test-subj="vmReportControls">
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
                selectedOptions={p.assetOptions.filter((o) => o.value === p.assetId)}
                onChange={(sel) => p.onAsset(sel[0]?.value ?? null)}
                placeholder="Pick an asset"
                isClearable={false}
              />
            </EuiFormRow>
          </EuiFlexItem>
        )}
        {p.mode === 'ranked' && (
          <EuiFlexItem grow={false}>
            <EuiFormRow label="Top N">
              <EuiFieldNumber value={p.topN} min={1} onChange={(e) => p.onTopN(Math.max(1, Number(e.target.value) || 1))} style={{ width: 90 }} />
            </EuiFormRow>
          </EuiFlexItem>
        )}
        <EuiFlexItem grow={false}>
          <EuiFormRow label="Confidence">
            <EuiSelect
              value={p.confidence}
              onChange={(e) => p.onConfidence(e.target.value as Confidence)}
              options={[
                { value: 'all', text: 'All' },
                { value: 'confirmed', text: 'Confirmed only' },
                { value: 'potential', text: 'Potential only' },
              ]}
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFormRow label="Severity">
            <EuiCheckboxGroup
              options={severityCheckboxes}
              idToSelectedMap={severitySelection}
              onChange={(id) => p.onToggleSeverity(id as Severity)}
              className="vmSeverityGroup"
            />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFormRow label="Per-asset CVE cap (PDF)">
            <EuiFieldNumber value={p.pdfCap} min={1} onChange={(e) => p.onPdfCap(Math.max(1, Number(e.target.value) || 1))} style={{ width: 110 }} />
          </EuiFormRow>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFormRow label="On an attack path" display="center">
            <EuiSwitch label="" checked={p.onPath} onChange={(e) => p.onOnPath(e.target.checked)} />
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
    </EuiPanel>
  );
}
