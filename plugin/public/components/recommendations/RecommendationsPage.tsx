// The recommendations page: the network-wide action plan (lib/recommendations)
// with a shared status per item.
import React, { useMemo, useState } from 'react';
import {
  EuiBadge,
  EuiButtonGroup,
  EuiCallOut,
  EuiEmptyPrompt,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiHorizontalRule,
  EuiLink,
  EuiLoadingSpinner,
  EuiPanel,
  EuiProgress,
  EuiSelect,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { RecommendationStatus } from '../../../common';
import { RISK_META, TIER_META } from '../../lib/risk';
import { Severity } from '../../lib/report';
import { useGraph } from '../../lib/graph';
import { useVulnerabilities } from '../../lib/vulnerabilities';
import { useAttackPaths } from '../../lib/attackPathsData';
import { useRecommendations } from '../../lib/recommendationsData';
import { useOfflineHosts } from '../../lib/liveness';
import { buildRecommendations, Recommendation, recommendationProgress } from '../../lib/recommendations';
import { SEV_META } from '../vulnreport/format';
import { Chip } from '../vulnreport/parts';

const severityChip = (sev: Severity | null) =>
  sev ? <Chip color={SEV_META[sev].color} label={SEV_META[sev].label} /> : <Chip color={RISK_META.unscored.color} label="Advisory" />;

const STATUS_OPTIONS: Array<{ id: RecommendationStatus; label: string }> = [
  { id: 'open', label: 'Open' },
  { id: 'in_progress', label: 'In progress' },
  { id: 'done', label: 'Done' },
  { id: 'accepted_risk', label: 'Accepted risk' },
];

const SEVERITY_FILTER = [
  { value: 'all', text: 'All severities' },
  { value: 'critical', text: 'Critical' },
  { value: 'high', text: 'High' },
  { value: 'medium', text: 'Medium' },
  { value: 'low', text: 'Low' },
  { value: 'advisory', text: 'Advisory' },
];

function RecPanel({ rec, onStatus }: { rec: Recommendation; onStatus: (s: RecommendationStatus) => void }) {
  const muted = rec.status === 'done' || rec.status === 'accepted_risk';
  return (
    <EuiPanel paddingSize="m" hasBorder className={`vmRec ${muted ? 'vmRecMuted' : ''}`}>
      <div className="vmRec__head">
        {rec.tier && <Chip color={TIER_META[rec.tier].color} label={`${rec.tier}${rec.ovss != null ? ` · OVSS ${rec.ovss}` : ''}`} />}
        {severityChip(rec.severity)}
        <EuiTitle size="xs"><h3 className="vmRec__title">{rec.title}</h3></EuiTitle>
        <EuiBadge color="hollow">{rec.affectedCount} asset{rec.affectedCount === 1 ? '' : 's'}</EuiBadge>
      </div>
      <EuiText size="s"><p>{rec.action}</p></EuiText>
      {rec.reference && (
        <EuiText size="xs">
          <p>
            <EuiLink href={rec.reference.url} target="_blank">{rec.reference.title}</EuiLink>
            {rec.category ? ` · ${rec.category}` : ''}
          </p>
        </EuiText>
      )}
      <EuiSpacer size="xs" />
      <div className="vmRec__assets">
        {rec.affected.map((a) => (
          <EuiBadge key={a.id} color="default">{a.name}</EuiBadge>
        ))}
      </div>
      {rec.onPathCount > 0 && (
        <EuiText size="xs" color="subdued"><p>On {rec.onPathCount} attack path{rec.onPathCount === 1 ? '' : 's'}.</p></EuiText>
      )}
      <EuiSpacer size="s" />
      <EuiButtonGroup
        legend={`Status for ${rec.title}`}
        idSelected={rec.status}
        onChange={(id) => onStatus(id as RecommendationStatus)}
        options={STATUS_OPTIONS}
        buttonSize="compressed"
      />
    </EuiPanel>
  );
}

export function RecommendationsPage() {
  const { graph, loading: gLoading, error: gError } = useGraph();
  const { doc: vulns, loading: vLoading, error: vError } = useVulnerabilities();
  const { doc: attackPaths } = useAttackPaths();
  const { file, setStatus } = useRecommendations();

  const [statusFilter, setStatusFilter] = useState<'all' | RecommendationStatus>('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  // Optimistic per-item overrides, so the status flips before the POST resolves.
  const [pending, setPending] = useState<Record<string, RecommendationStatus>>({});

  // Offline hosts are not counted as affected assets.
  const offline = useOfflineHosts();
  const offlineIds = useMemo(() => new Set(offline.map((n) => n.node_id)), [offline]);
  const recs = useMemo(
    () => (graph && vulns ? buildRecommendations(graph, vulns, attackPaths, file, offlineIds) : []),
    [graph, vulns, attackPaths, file, offlineIds]
  );
  // Apply optimistic overrides on top of the server-built status.
  const withPending = useMemo(
    () => recs.map((r) => (pending[r.key] ? { ...r, status: pending[r.key] } : r)),
    [recs, pending]
  );
  const progress = useMemo(() => recommendationProgress(withPending), [withPending]);

  const onStatus = (key: string, status: RecommendationStatus) => {
    setPending((p) => ({ ...p, [key]: status }));
    setStatus(key, status).catch(() => setPending((p) => { const { [key]: _drop, ...rest } = p; return rest; }));
  };

  if ((gLoading && !graph) || (vLoading && !vulns)) return <EuiLoadingSpinner size="xl" />;
  if (gError) return <EuiCallOut color="danger" iconType="alert" title={gError} />;
  if (vError) return <EuiCallOut color="danger" iconType="alert" title={vError} />;

  if (!graph || !vulns || vulns.metadata.state === 'absent') {
    return (
      <EuiPanel paddingSize="l">
        <EuiEmptyPrompt
          iconType="bullseye"
          title={<h2>No recommendations yet</h2>}
          body={<p>Run a scan to produce the per-asset findings, then this action plan becomes available.</p>}
          data-test-subj="vmRecsAbsent"
        />
      </EuiPanel>
    );
  }

  const shown = withPending.filter(
    (r) =>
      (statusFilter === 'all' || r.status === statusFilter) &&
      (severityFilter === 'all' || (severityFilter === 'advisory' ? r.severity === null : r.severity === severityFilter))
  );

  return (
    <div className="vmRecsPage">
      <EuiPanel paddingSize="m" hasBorder>
        <EuiText size="s"><p><strong>{progress.addressed}</strong> of <strong>{progress.total}</strong> addressed</p></EuiText>
        <EuiProgress value={progress.addressed} max={progress.total || 1} size="s" color="primary" />
        <EuiSpacer size="m" />
        <EuiFlexGroup gutterSize="m" wrap>
          <EuiFlexItem grow={false}>
            <EuiFormRow label="Status">
              <EuiSelect
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as 'all' | RecommendationStatus)}
                options={[{ value: 'all', text: 'All' }, ...STATUS_OPTIONS.map((o) => ({ value: o.id, text: o.label }))]}
              />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiFormRow label="Severity">
              <EuiSelect value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} options={SEVERITY_FILTER} />
            </EuiFormRow>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiPanel>

      <EuiSpacer size="l" />

      {recs.length === 0 ? (
        <EuiEmptyPrompt iconType="bullseye" title={<h2>Nothing to act on from the current scan.</h2>} data-test-subj="vmRecsEmpty" />
      ) : shown.length === 0 ? (
        <EuiText color="subdued"><p>No recommendations match the current filters.</p></EuiText>
      ) : (
        shown.map((r) => (
          <React.Fragment key={r.key}>
            <RecPanel rec={r} onStatus={(s) => onStatus(r.key, s)} />
            <EuiSpacer size="m" />
          </React.Fragment>
        ))
      )}

      <EuiHorizontalRule margin="m" />
      <EuiText size="xs" color="subdued">
        <p>
          Actions come only from the current scan's findings: configuration remediation is the publisher's own text, and
          CVE guidance is generic and never names an invented fixed version. Progress is shared across viewers and survives
          rescans.
        </p>
      </EuiText>
    </div>
  );
}
