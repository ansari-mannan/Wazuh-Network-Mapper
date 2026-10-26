/**
 * @jest-environment jsdom
 */
import React from 'react';
import ReactDOM from 'react-dom';
import { act } from 'react-dom/test-utils';

const states: any[] = [
  { status: 'running', trigger: 'manual', message: null, startedAt: '2026-10-26T09:00:00Z', finishedAt: null },
  {
    status: 'idle',
    trigger: 'manual',
    message: 'Scan completed; graph updated.',
    startedAt: '2026-10-26T09:00:00Z',
    finishedAt: '2026-10-26T09:05:00Z',
    warnings: [{ type: 'snmp_fallback', devices: ['sw1', 'sw2'] }],
    snmp: { entered: [], server: ['device:1', 'device:2'] },
  },
];
const toasts = { addWarning: jest.fn(), addSuccess: jest.fn(), addDanger: jest.fn() };
const mockServices = { http: { get: async () => states.shift() ?? states[0] }, notifications: { toasts } };
jest.mock('./services', () => ({ useServices: () => mockServices }));
jest.mock('./graph', () => ({ useGraph: () => ({ reload: () => undefined }) }));

import { ScanProvider } from './scan';

it('shows a warning toast when the finished scan has an SNMP fallback', async () => {
  jest.useFakeTimers();
  const root = document.createElement('div');
  await act(async () => {
    ReactDOM.render(<ScanProvider>{null}</ScanProvider>, root);
  });
  await act(async () => {
    jest.advanceTimersByTime(1600); // the next poll while running
  });
  expect(toasts.addSuccess).not.toHaveBeenCalled();
  expect(toasts.addWarning).toHaveBeenCalledWith({
    title: 'Scan completed with a warning',
    text: "The community you entered didn't work on any device. The server's SNMP settings were used for all 2 (sw1, sw2).",
  });
  ReactDOM.unmountComponentAtNode(root);
  jest.useRealTimers();
});
