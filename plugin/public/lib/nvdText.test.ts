import { nvdKeyStatus, nvdToastLine, nvdToastText } from './nvdText';

describe('NVD key text', () => {
  it('says in use or not set', () => {
    expect(nvdKeyStatus(true)).toBe('in use');
    expect(nvdKeyStatus(false)).toBe('not set');
    expect(nvdKeyStatus(undefined)).toMatch(/^unknown/);
  });

  it('adds a toast line only when the stage ran', () => {
    expect(nvdToastText(true)).toBe('NVD: key in use');
    expect(nvdToastText(false)).toBe('NVD: no key (slower lookups)');
    expect(nvdToastText(null)).toBeUndefined();
  });

  describe('in the scan-complete toast', () => {
    const memory = () => {
      const items: Record<string, string> = {};
      return { getItem: (k: string) => items[k] ?? null, setItem: (k: string, v: string) => (items[k] = v) };
    };

    it('shows on the first scan, then only when the state changes', () => {
      const storage = memory();
      expect(nvdToastLine(false, storage)).toBe('NVD: no key (slower lookups)'); // first scan seen
      expect(nvdToastLine(false, storage)).toBeUndefined(); // unchanged
      expect(nvdToastLine(true, storage)).toBe('NVD: key in use'); // not set -> in use
      expect(nvdToastLine(true, storage)).toBeUndefined();
      expect(nvdToastLine(null, storage)).toBeUndefined(); // no device-CVE stage: says nothing
      expect(nvdToastLine(true, storage)).toBeUndefined(); // and forgets nothing
      expect(nvdToastLine(false, storage)).toBe('NVD: no key (slower lookups)'); // in use -> not set
    });

    it('shows every time when the browser keeps nothing', () => {
      const broken = { getItem: () => { throw new Error('blocked'); }, setItem: () => { throw new Error('blocked'); } };
      expect(nvdToastLine(true, broken)).toBe('NVD: key in use');
      expect(nvdToastLine(true, broken)).toBe('NVD: key in use');
      expect(nvdToastLine(true, null)).toBe('NVD: key in use');
    });
  });
});
