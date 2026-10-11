import { applyRecommendationStatus, readRecommendations, recommendationsFilePath } from './recommendations';

describe('recommendationsFilePath', () => {
  it('places the tracker beside the graph', () => {
    expect(recommendationsFilePath('/data/graph.json')).toBe('/data/recommendations.json');
  });
});

describe('readRecommendations', () => {
  it('reads an empty tracker when absent or invalid', () => {
    expect(readRecommendations(null)).toEqual({ statuses: {} });
    expect(readRecommendations('not json')).toEqual({ statuses: {} });
    expect(readRecommendations('[]')).toEqual({ statuses: {} });
  });

  it('reads a valid tracker', () => {
    const doc = { statuses: { 'config:x': { status: 'done', updated: 'now' } } };
    expect(readRecommendations(JSON.stringify(doc))).toEqual(doc);
  });
});

describe('applyRecommendationStatus', () => {
  it('upserts an item with a timestamp', () => {
    const next = applyRecommendationStatus({ statuses: {} }, 'config:x', 'in_progress');
    expect(next.statuses['config:x'].status).toBe('in_progress');
    expect(typeof next.statuses['config:x'].updated).toBe('string');
  });

  it('deletes the entry when set back to open', () => {
    const current = { statuses: { 'config:x': { status: 'done' as const, updated: 'now' } } };
    expect(applyRecommendationStatus(current, 'config:x', 'open')).toEqual({ statuses: {} });
  });

  it('does not mutate the input', () => {
    const current = { statuses: { a: { status: 'done' as const, updated: 'now' } } };
    applyRecommendationStatus(current, 'a', 'open');
    expect(current.statuses.a).toBeDefined();
  });
});
