import { ScanState } from '../../common';
import { scanEndToast } from './scan';

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
