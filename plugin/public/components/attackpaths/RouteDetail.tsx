// One route in full: each step, its likelihood and source, and the findings
// on the assets it crosses.
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
import { AttackPathsMetadata, AttackRoute, AttackStartingPoint, AttackStep } from '../../../common';
import { RISK_META } from '../../lib/risk';
import { startKindLabel, stepText } from '../../lib/attackPaths';
import { TierReason } from '../../lib/ovssText';
import { TierReasonLine, TierTip } from '../layout/TierReason';

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

function TakeoverStep({ step, nameOf, why }: { step: AttackStep; nameOf: (id: string) => string; why: TierReason | null }) {
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
        {typeof step.destination_ovss === 'number' && (
          <EuiFlexItem grow={false}>
            <TierTip why={why}>
              <EuiBadge color="hollow" data-test-subj="vmStepScore">
                OVSS {step.destination_ovss} / 10
              </EuiBadge>
            </TierTip>
          </EuiFlexItem>
        )}
      </EuiFlexGroup>
      <TierReasonLine why={why} />
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
  startName,
  spare,
  reasonOf,
  metadata,
  onShowOnMap,
}: {
  route: AttackRoute;
  nameOf: (id: string) => string;
  startName: string; // the start in words (spare ports: their switch, and if it is the target)
  spare?: AttackStartingPoint; // the route's start when it is spare switch ports
  reasonOf: (id: string) => TierReason | null; // why the node has its tier
  metadata: AttackPathsMetadata;
  onShowOnMap: () => void;
}) {
  return (
    <EuiPanel paddingSize="l" hasBorder data-test-subj="vmRouteDetail">
      <EuiText size="s">
        <p>
          Assumes <strong>{startName}</strong> ({startKindLabel(route.start_kind)}) is already compromised.
        </p>
      </EuiText>
      <EuiSpacer size="m" />

      {spare && (
        <EuiPanel paddingSize="m" hasShadow={false} hasBorder data-test-subj="vmStepSpare">
          <EuiTitle size="xxs">
            <h4>
              Plug into a spare port in VLAN {spare.vlans[0]}
              {spare.switch && ` on ${spare.switch_label || nameOf(spare.switch)}`}
            </h4>
          </EuiTitle>
        </EuiPanel>
      )}
      {route.steps.map((step, i) => (
        <React.Fragment key={i}>
          {(i > 0 || spare) && (
            <div className="vmChainConnector" aria-hidden>
              <EuiIcon type="sortDown" size="m" />
            </div>
          )}
          {step.kind === 'transit' ? (
            <div className="vmTransit" data-test-subj="vmStepTransit">
              {stepText(step, nameOf).heading} — {stepText(step, nameOf).detail}
            </div>
          ) : (
            <TakeoverStep step={step} nameOf={nameOf} why={reasonOf(step.to)} />
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
          <p>
            Likelihood is NIST IR 7788&apos;s coarse three-value model (low / medium / high step
            complexity), shown as a percentage for legibility — not a precise probability. OVSS is
            the asset&apos;s highest finding score, out of 10, and breaks ties between equally likely
            routes. Higher is worse on both.
          </p>
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
      <EuiText size="xs" color="subdued" data-test-subj="vmTransitNote">
        <p>
          Switches, routers and access points along a route only carry the traffic between hosts;
          they are not compromised unless a step on the route says so.
        </p>
      </EuiText>
      <EuiSpacer size="s" />
      <EuiButton size="s" iconType="graphApp" onClick={onShowOnMap} data-test-subj="vmShowOnMap">
        Show on map
      </EuiButton>
    </EuiPanel>
  );
}
