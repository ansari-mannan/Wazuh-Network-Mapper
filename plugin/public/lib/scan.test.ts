import { ScanState } from '../../common';
import { backgroundScanText, scanEndToast } from './scan';

const ended = (status: ScanState['status'], trigger: ScanState['trigger']): ScanState => ({
  status,
  trigger,
  message: status === 'failed' ? 'nmap exploded' : 'Scan completed; graph updated.',
  startedAt: null,
  finishedAt: '2026-10-15T10:00:00Z',
  nvdKey: true,
});
const line = () => 'NVD: key in use';

describe('scanEndToast', () => {
  it('stays quiet when an automatic or scheduled scan succeeds', () => {
    expect(scanEndToast(ended('idle', 'automatic'), line)).toBeNull();
    expect(scanEndToast(ended('idle', 'scheduled'), line)).toBeNull();
  });

  it('still reports their failures', () => {
    for (const trigger of ['automatic', 'scheduled'] as const) {
      expect(scanEndToast(ended('failed', trigger), line)).toEqual({
        kind: 'danger',
        title: 'Scan failed; the previous graph is still shown',
        text: 'nmap exploded',
      });
    }
  });

  it('keeps the toast for a manual scan, NVD line included', () => {
    expect(scanEndToast(ended('idle', 'manual'), line)).toEqual({
      kind: 'success',
      title: 'Scan completed; graph updated',
      text: 'NVD: key in use',
    });
  });

  it('asks for the NVD line only when it shows a success toast', () => {
    const nvd = jest.fn(line);
    scanEndToast(ended('idle', 'scheduled'), nvd);
    scanEndToast(ended('failed', 'manual'), nvd);
    expect(nvd).not.toHaveBeenCalled();
  });
});

describe('backgroundScanText', () => {
  const running = (trigger: ScanState['trigger'], stage: string | null): ScanState => ({
    status: 'running',
    trigger,
    stage,
    message: null,
    startedAt: '2026-10-15T10:00:00Z',
    finishedAt: null,
  });
  const now = Date.parse('2026-10-15T10:00:42Z');

  it('offers to stop an automatic or scheduled scan, with its stage and age', () => {
    expect(backgroundScanText(running('automatic', 'Looking up device CVEs in NVD'), now)).toBe(
      'An automatic scan is running (stage: Looking up device CVEs in NVD, 42 s in)'
    );
    expect(backgroundScanText(running('scheduled', null), now)).toBe('A scheduled scan is running (stage: starting, 42 s in)');
  });

  it('offers nothing for a manual scan or when none runs', () => {
    expect(backgroundScanText(running('manual', 'x'), now)).toBeNull();
    expect(backgroundScanText({ ...running('automatic', 'x'), status: 'idle' }, now)).toBeNull();
    expect(backgroundScanText(null, now)).toBeNull();
  });
});
