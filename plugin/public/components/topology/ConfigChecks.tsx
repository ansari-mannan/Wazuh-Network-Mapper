import React from 'react';
import {
  EuiBadge,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLink,
  EuiNotificationBadge,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { ConfigFinding, DeviceNode, Metadata } from '../../../common';
import {
  evidenceLines,
  noChecklistText,
  referenceText,
  severityKey,
  severityLabel,
  sortFindings,
  summaryLine,
} from '../../lib/checklistText';
import { RISK_META } from '../../lib/risk';

// A device's configuration checks (backend/vulnmapper/checklist): the failed
// checks in full, the ones that could not be decided listed quietly. They do
// not change the risk colour or score.

export function configSeverityColor(severity: string | null): string {
  const key = severityKey(severity);
  return key === 'advisory' ? 'hollow' : RISK_META[key].color;
}

function Finding({ f }: { f: ConfigFinding }) {
  const evidence = evidenceLines(f.id, f.evidence);
  return (
    <EuiPanel paddingSize="s" hasShadow={false} hasBorder data-test-subj={`vmConfigFinding-${f.id}`}>
      <EuiFlexGroup justifyContent="spaceBetween" alignItems="center" responsive={false} gutterSize="s">
        <EuiFlexItem>
          <EuiText size="s">
            <strong>{f.title}</strong>
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiBadge color={configSeverityColor(f.severity)}>{severityLabel(f.severity)}</EuiBadge>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiText size="xs">
        <p>{f.why}</p>
      </EuiText>
      {evidence.length > 0 && (
        <EuiText size="xs" color="subdued" className="vmConfigLines">
          {evidence.map((line) => (
            <p key={line}>{line}</p>
          ))}
        </EuiText>
      )}
      <EuiText size="xs">
        <p>
          <strong>Fix:</strong> {f.remediation}
        </p>
      </EuiText>
      <EuiText size="xs" color="subdued">
        <p>
          {f.references.map((r, i) => (
            <React.Fragment key={`${r.rule_id}:${i}`}>
              {i > 0 && ' · '}
              <EuiLink href={r.url} target="_blank" external title={r.title}>
                {referenceText(r)}
              </EuiLink>
            </React.Fragment>
          ))}
          {f.cwe && `${f.references.length ? ' · ' : ''}${f.cwe}`}
        </p>
      </EuiText>
    </EuiPanel>
  );
}

export function ConfigChecks({ node, meta }: { node: DeviceNode; meta: Metadata | undefined }) {
  const summary = node.config_summary;
  const failed = node.config_findings || [];
  const quiet = (node.config_checks || []).filter((c) => c.result === 'unknown' || c.result === 'not_checked');
  const source = meta?.checklist?.source;
  return (
    <EuiPanel paddingSize="m" hasShadow={false} hasBorder data-test-subj="vmConfigChecks">
      <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiTitle size="xxs">
            <h3>Configuration checks</h3>
          </EuiTitle>
        </EuiFlexItem>
        {summary && (
          <EuiFlexItem grow={false}>
            <EuiNotificationBadge color="subdued">{failed.length}</EuiNotificationBadge>
          </EuiFlexItem>
        )}
      </EuiFlexGroup>
      <EuiSpacer size="s" />
      {!summary ? (
        <EuiText size="s" color="subdued" data-test-subj="vmConfigNone">
          <p>{noChecklistText(node, meta)}</p>
        </EuiText>
      ) : (
        <>
          <EuiText size="s" data-test-subj="vmConfigSummary">
            <p>{summaryLine(summary)}</p>
          </EuiText>
          {source && source !== 'scan' && (
            <EuiText size="xs" color="subdued">
              <p>From {source}, not from a scan.</p>
            </EuiText>
          )}
          {sortFindings(failed).map((f) => (
            <React.Fragment key={f.id}>
              <EuiSpacer size="s" />
              <Finding f={f} />
            </React.Fragment>
          ))}
          {quiet.length > 0 && (
            <>
              <EuiSpacer size="s" />
              <EuiText size="xs" color="subdued" className="vmConfigLines" data-test-subj="vmConfigQuiet">
                {quiet.map((c) => (
                  <p key={c.id}>
                    {c.title}: {c.result === 'unknown' ? 'unknown' : 'not checked'}
                    {c.reason ? `, ${c.reason}` : ''}.
                  </p>
                ))}
              </EuiText>
            </>
          )}
        </>
      )}
    </EuiPanel>
  );
}
