import { isDismissed, rememberDismissed } from './dismissed';

function memory() {
  const items: Record<string, string> = {};
  return { getItem: (k: string) => items[k] ?? null, setItem: (k: string, v: string) => (items[k] = v) };
}

const broken = {
  getItem: () => {
    throw new Error('SecurityError');
  },
  setItem: () => {
    throw new Error('QuotaExceededError');
  },
};

describe('dismissed notes', () => {
  it('remembers a dismissal by its key only', () => {
    const s = memory();
    rememberDismissed('tls_unverified:Wazuh Indexer', s);
    expect(isDismissed('tls_unverified:Wazuh Indexer', s)).toBe(true);
    expect(isDismissed('tls_unverified:Wazuh Indexer,Wazuh Manager API', s)).toBe(false);
  });

  it('shows the note when storage throws or is missing', () => {
    expect(() => rememberDismissed('k', broken)).not.toThrow();
    expect(isDismissed('k', broken)).toBe(false);
    expect(isDismissed('k', null)).toBe(false);
  });
});
