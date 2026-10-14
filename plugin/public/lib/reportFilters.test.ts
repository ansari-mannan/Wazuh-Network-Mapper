import { DEFAULT_FILTERS, filterBadges, resultText, sameFilters, withoutFilter } from './reportFilters';

const name = (id: string) => id.toUpperCase();

describe('staged report filters', () => {
  it('compares filter sets, ignoring severity order', () => {
    expect(sameFilters(DEFAULT_FILTERS, { ...DEFAULT_FILTERS })).toBe(true);
    expect(sameFilters(DEFAULT_FILTERS, { ...DEFAULT_FILTERS, severities: [...DEFAULT_FILTERS.severities].reverse() })).toBe(true);
    expect(sameFilters(DEFAULT_FILTERS, { ...DEFAULT_FILTERS, severities: ['critical'] })).toBe(false);
    expect(sameFilters(DEFAULT_FILTERS, { ...DEFAULT_FILTERS, topN: 5 })).toBe(false);
    expect(sameFilters(DEFAULT_FILTERS, { ...DEFAULT_FILTERS, onPath: true })).toBe(false);
  });

  it('gives no badge for the defaults', () => {
    expect(filterBadges(DEFAULT_FILTERS, 'ranked', name)).toEqual([]);
  });

  it('gives one badge per narrowing filter, for the view shown', () => {
    const f = { ...DEFAULT_FILTERS, assetId: 'a1', topN: 5, severities: ['high' as const, 'critical' as const], confidence: 'confirmed' as const, onPath: true };
    expect(filterBadges(f, 'ranked', name).map((b) => b.label)).toEqual([
      'Top 5',
      'Severity: Critical, High',
      'Confirmed only',
      'On an attack path',
    ]);
    expect(filterBadges(f, 'single', name).map((b) => b.label)[0]).toBe('Asset: A1');
  });

  it('removes one filter back to its default', () => {
    const f = { ...DEFAULT_FILTERS, severities: ['low' as const], confidence: 'potential' as const };
    expect(withoutFilter(f, 'confidence')).toEqual({ ...f, confidence: 'all' });
    expect(withoutFilter(f, 'severities').severities).toEqual(DEFAULT_FILTERS.severities);
    expect(withoutFilter(f, 'severities').severities).not.toBe(DEFAULT_FILTERS.severities);
  });

  it('counts what is shown', () => {
    expect(resultText(3, 41)).toBe('Showing 3 assets, 41 findings');
    expect(resultText(1, 1)).toBe('Showing 1 asset, 1 finding');
  });
});
