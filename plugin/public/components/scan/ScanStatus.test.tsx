/**
 * @jest-environment jsdom
 */
import React from 'react';
import ReactDOM from 'react-dom';
import { act } from 'react-dom/test-utils';
import { ScanState } from '../../../common';
import { ScanStatus } from './ScanStatus';

const NAMES = ['CYFOR-HP-Switch', 'L2-Switch'];
const done = (extra: Partial<ScanState>): ScanState => ({
  status: 'idle',
  trigger: 'manual',
  message: 'Scan completed; graph updated.',
  startedAt: '2026-10-26T09:00:00Z',
  finishedAt: '2026-10-26T09:05:00Z',
  ...extra,
});

function render(scan: ScanState) {
  const root = document.createElement('div');
  act(() => {
    ReactDOM.render(<ScanStatus scan={scan} />, root);
  });
  const box = root.querySelector('[data-test-subj="vmScanStatus-done"]')!;
  const out = { className: box.className, title: box.querySelector('.euiCallOutHeader__title')?.textContent, text: box.textContent || '' };
  ReactDOM.unmountComponentAtNode(root);
  return out;
}

it('is green when the typed community worked on every device', () => {
  const box = render(done({ warnings: [], snmp: { entered: ['device:a', 'device:b'], server: [] } }));
  expect(box.title).toBe('Last scan completed');
  expect(box.className).toContain('euiCallOut--success');
});

it('is amber and names the devices when some fell back', () => {
  const box = render(done({ warnings: [{ type: 'snmp_fallback', devices: NAMES }], snmp: { entered: ['device:c'], server: ['device:a', 'device:b'] } }));
  expect(box.title).toBe('Scan completed with a warning');
  expect(box.className).toContain('euiCallOut--warning');
  expect(box.text).toContain("The community you entered didn't work on CYFOR-HP-Switch, L2-Switch; the server's SNMP settings were used for them.");
});

it('says when the typed community worked on no device', () => {
  const box = render(done({ warnings: [{ type: 'snmp_fallback', devices: NAMES }], snmp: { entered: [], server: ['device:a', 'device:b'] } }));
  expect(box.title).toBe('Scan completed with a warning');
  expect(box.text).toContain("The community you entered didn't work on any device. The server's SNMP settings were used for all 2 (CYFOR-HP-Switch, L2-Switch).");
});

it('is amber for an empty crawl, a failed stage or invalid targets', () => {
  for (const w of [{ type: 'crawl_empty', reason: 'no seed' }, { type: 'stage_failed', stage: 'x', error: 'E' }, { type: 'targets_invalid' }]) {
    expect(render(done({ warnings: [w] })).title).toBe('Scan completed with a warning');
  }
});
