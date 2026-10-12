import { PAGES } from './pages';

describe('PAGES', () => {
  it('orders the risk pages attack paths, vulnerability report, recommendations', () => {
    expect(PAGES.filter((p) => p.group === 'risk').map((p) => p.id)).toEqual([
      'attack-paths',
      'vulnerabilities',
      'recommendations',
    ]);
  });
});
