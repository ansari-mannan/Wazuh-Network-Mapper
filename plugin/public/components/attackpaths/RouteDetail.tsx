import React from 'react';
import {
  EuiAccordion,
  EuiBadge,
  EuiButton,
  EuiFlexGroup,
  EuiFlexItem,
  EuiIcon,
  EuiLink,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { AttackPathsMetadata, AttackRoute, AttackStep } from '../../../common';
import { RISK_META } from '../../lib/risk';
import { startKindLabel, stepText } from '../../lib/attackPaths';

// Context findings carry the publisher's own severity (null = advisory).
function FindingBadges({ step }: { step: AttackStep }) {
  const findings = step.context_findings || [];
  if (findings.length === 0) return null;
  return (
    <EuiFlexGroup gutterSize="xs" wrap responsive={false} data-test-subj="vmStepFindings">
      {findings.map((f) => (
        <EuiFlexItem grow={false} key={f.id}>
          <EuiBadge color={f.severity ? RISK_META[f.severity].color : 'hollow'}>
            {f.title}
            {f.severity ? ` · ${f.severity}` : ' · advisory'}
          </EuiBadge>
        </EuiFlexItem>
      ))}
    </EuiFlexGroup>
  );
}

function TakeoverStep({ step, nameOf }: { step: AttackStep; nameOf: (id: string) => string }) {
  const text = stepText(step, nameOf);
  return (
    <EuiPanel paddingSize="m" hasShadow={false} hasBorder data-test-subj="vmStepTakeover">
      <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiIcon type="securitySignalDetected" color="danger" />
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiTitle size="xxs">
            <h4>{text.heading}</h4>
          </EuiTitle>
        </EuiFlexItem>
        {typeof step.destination_base_score === 'number' && (
          <EuiFlexItem grow={false}>
            <EuiBadge color="hollow" data-test-subj="vmStepScore">
              base score {step.destination_base_score}
            </EuiBadge>
          </EuiFlexItem>
        )}
      </EuiFlexGroup>
      <EuiSpacer size="xs" />
      <EuiText size="s" color="subdued">
        <p>
          {step.kind === 'weakness' ? 'Weakness: ' : 'Misconfiguration: '}
          <span className={step.cve ? 'vmMono' : undefined}>{text.detail}</span>
        </p>
      </EuiText>
      {(step.context_findings || []).length > 0 && (
        <>
          <EuiSpacer size="s" />
          <FindingBadges step={step} />
        </>
      )}
    </EuiPanel>
  );
}

export function RouteDetail({
  route,
  nameOf,
  metadata,
  onShowOnMap,
}: {
  route: AttackRoute;
  nameOf: (id: string) => string;
  metadata: AttackPathsMetadata;
  onShowOnMap: () => void;
}) {
  return (
    <EuiPanel paddingSize="l" hasBorder data-test-subj="vmRouteDetail">
      <EuiText size="s">
        <p>
          Assumes <strong>{nameOf(route.start)}</strong> ({startKindLabel(route.start_kind)}) is already compromised.
        </p>
      </EuiText>
      <EuiSpacer size="m" />

      {route.steps.map((step, i) => (
        <React.Fragment key={i}>
          {i > 0 && (
            <div className="vmChainConnector" aria-hidden>
              <EuiIcon type="sortDown" size="m" />
            </div>
          )}
          {step.kind === 'transit' ? (
            <div className="vmTransit" data-test-subj="vmStepTransit">
              {stepText(step, nameOf).heading} — {stepText(step, nameOf).detail}
            </div>
          ) : (
            <TakeoverStep step={step} nameOf={nameOf} />
          )}
        </React.Fragment>
      ))}

      <EuiSpacer size="m" />
      <EuiText size="s" color="subdued" data-test-subj="vmNarrative">
        <p>{route.narrative}</p>
      </EuiText>

      <EuiSpacer size="m" />
      <EuiAccordion id={`vmScoring-${route.start}`} buttonContent="How this is scored" paddingSize="s">
        <EuiText size="xs" color="subdued">
          <p>Sources</p>
          <ul>
            {(metadata.sources || []).map((s) => (
              <li key={s.url}>
                <EuiLink href={s.url} target="_blank" external>
                  {s.title}
                </EuiLink>
              </li>
            ))}
          </ul>
          <p>Limits</p>
          <ul>
            {(metadata.limits || []).map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </EuiText>
      </EuiAccordion>

      <EuiSpacer size="m" />
      <EuiButton size="s" iconType="graphApp" onClick={onShowOnMap} data-test-subj="vmShowOnMap">
        Show on map
      </EuiButton>
    </EuiPanel>
  );
}
