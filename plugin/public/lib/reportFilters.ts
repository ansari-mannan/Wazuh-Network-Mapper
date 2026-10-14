// The vulnerability report's staged filters: the controls edit a draft, and
// the report shows only what was applied (Apply, Enter, Reset or removing a
// badge). No React, no theme: unit tested.
import { ReportFilters, Severity, SEVERITIES } from './report';

export type Confidence = ReportFilters['confidence'];

export interface StagedFilters {
  /** the single-asset view's asset */
  assetId: string | null;
  severities: Severity[];
  confidence: Confidence;
  onPath: boolean;
  /** how many assets the ranked view lists */
  topN: number;
}

export const DEFAULT_FILTERS: StagedFilters = {
  assetId: null,
  severities: SEVERITIES.slice(),
  confidence: 'all',
  onPath: false,
  topN: 10,
};

/** Whether two filter sets show the same report (severity order does not matter). */
export function sameFilters(a: StagedFilters, b: StagedFilters): boolean {
  return (
    a.assetId === b.assetId &&
    a.confidence === b.confidence &&
    a.onPath === b.onPath &&
    a.topN === b.topN &&
    a.severities.length === b.severities.length &&
    a.severities.every((s) => b.severities.includes(s))
  );
}

export type FilterKey = keyof StagedFilters;

export interface FilterBadge {
  key: FilterKey;
  label: string;
}

const CONFIDENCE_LABEL: Record<Confidence, string> = {
  all: 'All',
  confirmed: 'Confirmed only',
  potential: 'Potential only',
};

const capitalised = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/**
 * The applied filters that narrow the report, one badge each, for the view
 * shown: the asset only in the single-asset view, Top N only in the ranked one.
 */
export function filterBadges(
  f: StagedFilters,
  mode: 'ranked' | 'single',
  assetName: (id: string) => string
): FilterBadge[] {
  const badges: FilterBadge[] = [];
  if (mode === 'single' && f.assetId) badges.push({ key: 'assetId', label: `Asset: ${assetName(f.assetId)}` });
  if (mode === 'ranked' && f.topN !== DEFAULT_FILTERS.topN) badges.push({ key: 'topN', label: `Top ${f.topN}` });
  if (f.severities.length < SEVERITIES.length) {
    const shown = SEVERITIES.filter((s) => f.severities.includes(s)).map(capitalised);
    badges.push({ key: 'severities', label: `Severity: ${shown.join(', ') || 'none'}` });
  }
  if (f.confidence !== 'all') badges.push({ key: 'confidence', label: CONFIDENCE_LABEL[f.confidence] });
  if (f.onPath) badges.push({ key: 'onPath', label: 'On an attack path' });
  return badges;
}

/** The filters with one of them back at its default (a removed badge). */
export function withoutFilter(f: StagedFilters, key: FilterKey): StagedFilters {
  const reset = key === 'severities' ? SEVERITIES.slice() : DEFAULT_FILTERS[key];
  return { ...f, [key]: reset };
}

/** "Showing 3 assets, 41 findings" for the report as filtered. */
export function resultText(assets: number, findings: number): string {
  const n = (count: number, word: string) => `${count} ${word}${count === 1 ? '' : 's'}`;
  return `Showing ${n(assets, 'asset')}, ${n(findings, 'finding')}`;
}
