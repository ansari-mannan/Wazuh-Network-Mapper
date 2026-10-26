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

  it('warns when a typed community fell back on some or all devices, not when it worked everywhere', () => {
    const fallback = { type: 'snmp_fallback', devices: ['CYFOR-HP-Switch', 'L2-Switch'] };
    const some = { ...ended('idle', 'manual'), warnings: [fallback], snmp: { entered: ['device:a'], server: ['device:b', 'device:c'] } };
    expect(scanEndToast(some, line)).toEqual({
      kind: 'warning',
      title: 'Scan completed with a warning',
      text:
        "The community you entered didn't work on CYFOR-HP-Switch, L2-Switch; the server's SNMP settings were used for them. " +
        'NVD: key in use',
    });
    const all = { ...some, snmp: { entered: [], server: ['device:b', 'device:c'] } };
    expect(scanEndToast(all, line)?.text).toMatch(/^The community you entered didn't work on any device\. .* all 2 \(CYFOR-HP-Switch, L2-Switch\)\./);
    const none = { ...some, warnings: [], snmp: { entered: ['device:a'], server: [] } };
    expect(scanEndToast(none, line)?.kind).toBe('success');
  });

  it('warns for the other graph warnings too', () => {
    const failed = { ...ended('idle', 'manual'), warnings: [{ type: 'stage_failed', stage: 'nmap service scan', error: 'OSError' }] };
    expect(scanEndToast(failed, line)?.kind).toBe('warning');
    const tls = { ...ended('idle', 'manual'), warnings: [{ type: 'tls_unverified', services: ['Wazuh'] }] };
    expect(scanEndToast(tls, line)?.kind).toBe('success'); // a note, not a warning
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
