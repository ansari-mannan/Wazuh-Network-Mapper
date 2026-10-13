// The report's charts. Inline SVG, so the colours survive the print stylesheet.
import React from 'react';
import { EuiText } from '@elastic/eui';
import { NODE_LEVEL_META, NodeLevel, TIER_META, TIERS } from '../../lib/risk';
import { ExecutiveSummary, Severity, SEVERITIES, SplitCounts } from '../../lib/report';
import { SEV_META } from './format';
import { Chip } from './parts';

const sevTotal = (c: Record<Severity, number>) => SEVERITIES.reduce((n, s) => n + c[s], 0);

// A KPI row straight from the executive summary; no invented figures.
export function StatBand({ exec }: { exec: ExecutiveSummary }) {
  const stats = [
    { value: `${exec.totalAssets}`, label: 'Total assets' },
    { value: `${exec.managed} of ${exec.totalHosts}`, label: 'Hosts with an agent' },
    { value: `${sevTotal(exec.counts.confirmed)}`, label: 'Confirmed findings' },
    { value: `${sevTotal(exec.counts.potential)}`, label: 'Potential findings' },
    ...TIERS.map((t) => ({ value: `${exec.tiers[t]}`, label: `${t} findings` })),
    { value: `${exec.onPathAssets}`, label: 'Assets on an attack path' },
  ];
  return (
    <div className="vmStatBand">
      {stats.map((s) => (
        <div className="vmStat" key={s.label}>
          <div className="vmStat__value">{s.value}</div>
          <div className="vmStat__label">{s.label}</div>
        </div>
      ))}
    </div>
  );
}

// One horizontal stacked bar: severity segments across a 0..100 track, scaled
// to `total` so rows share a scale. preserveAspectRatio="none" lets it fill the
// width; no text inside (it would distort), labels live in the legend.
function StackBar({ counts, total }: { counts: Record<Severity, number>; total: number }) {
  let x = 0;
  const segs = SEVERITIES.filter((s) => counts[s] > 0).map((s) => {
    const w = (counts[s] / total) * 100;
    const seg = { s, x, w };
    x += w;
    return seg;
  });
  return (
    <svg className="vmChart vmStackBar" viewBox="0 0 100 10" preserveAspectRatio="none" width="100%" height="12" role="presentation">
      <rect className="vmChartTrack" x="0" y="0" width="100" height="10" />
      {segs.map((g) => (
        <rect className="vmChartSeg" key={g.s} x={g.x} y="0" width={g.w} height="10" fill={SEV_META[g.s].color} />
      ))}
    </svg>
  );
}

// Findings by severity, split confirmed vs potential (both scaled to the grand
// total so their lengths are comparable), with a legend carrying the figures.
export function SeverityBar({ counts, split = true }: { counts: SplitCounts; split?: boolean }) {
  const grand = counts.total;
  if (!grand) return <EuiText size="xs" color="subdued"><p>No findings to chart.</p></EuiText>;
  const combined = Object.fromEntries(SEVERITIES.map((s) => [s, counts.confirmed[s] + counts.potential[s]])) as Record<Severity, number>;
  const rows = split
    ? [{ label: 'Confirmed', c: counts.confirmed }, { label: 'Potential', c: counts.potential }]
    : [{ label: '', c: combined }];
  return (
    <div className="vmSevBar">
      {rows.map((r) => (
        <div className="vmBarRow" key={r.label || 'all'}>
          {r.label && <span className="vmBarRow__label">{r.label}</span>}
          <StackBar counts={r.c} total={grand} />
        </div>
      ))}
      <div className="vmChartLegend">
        {SEVERITIES.filter((s) => combined[s] > 0).map((s) => (
          <span className="vmCountChip" key={s}>
            <Chip color={SEV_META[s].color} label={`${combined[s]} ${SEV_META[s].label.toLowerCase()}`} />
          </span>
        ))}
      </div>
    </div>
  );
}

// Findings per OVSS tier as chips (colour and word), across every asset.
export function TierRow({ tiers }: { tiers: ExecutiveSummary['tiers'] }) {
  return (
    <div className="vmCountRow">
      <span className="vmCountRow__label">By OVSS tier:</span>
      {TIERS.map((t) => (
        <span key={t} className="vmCountChip">
          <Chip color={TIER_META[t].color} label={`${tiers[t]} ${t}`} />
        </span>
      ))}
      {tiers.Unrated > 0 && (
        <span className="vmCountChip">
          <Chip color={NODE_LEVEL_META.none.color} label={`${tiers.Unrated} unrated`} />
        </span>
      )}
    </div>
  );
}

// Top assets by total CVE count, each bar in the asset's map colour (its tier).
export function MostAtRisk({ items }: { items: Array<{ name: string; total: number; level: NodeLevel }> }) {
  const max = Math.max(...items.map((i) => i.total), 1);
  return (
    <div className="vmBarChart">
      {items.map((i) => (
        <div className="vmBarChart__row" key={i.name}>
          <span className="vmBarChart__name" title={i.name}>{i.name}</span>
          <svg className="vmChart vmBarChart__track" viewBox="0 0 100 10" preserveAspectRatio="none" width="100%" height="12" role="presentation">
            <rect className="vmChartSeg" x="0" y="0" width={(i.total / max) * 100} height="10" fill={NODE_LEVEL_META[i.level].color} />
          </svg>
          <span className="vmBarChart__value">{i.total}</span>
        </div>
      ))}
    </div>
  );
}
