import { nvdKeyStatus, nvdToastText } from './nvdText';

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
});
