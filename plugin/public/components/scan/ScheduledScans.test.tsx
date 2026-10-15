/**
 * @jest-environment jsdom
 */
import React from 'react';
import ReactDOM from 'react-dom';
import { act } from 'react-dom/test-utils';
import { ScheduleResponse } from '../../../common';

let mockSchedule: ScheduleResponse = {
  frequency: 'daily',
  dailyHour: 2,
  nextRun: '2026-10-14T02:00:00.000Z',
  timeZone: 'UTC',
  lastRun: { at: '2026-10-13T02:00:00.000Z', status: 'failed', message: 'No SNMP credential is set in the dashboard server environment' },
};
const mockServices = { http: { get: async () => mockSchedule }, notifications: {} };
jest.mock('../../lib/services', () => ({ useServices: () => mockServices }));
jest.mock('../../lib/scan', () => ({ useScan: () => ({ scan: null }) }));

import { ScheduledScans, shortIntervalWarning } from './ScheduledScans';

it('shows the choice, the next run and why the last scheduled scan failed', async () => {
  const root = document.createElement('div');
  await act(async () => {
    ReactDOM.render(<ScheduledScans />, root);
  });
  const text = root.textContent || '';
  expect((root.querySelector('[data-test-subj="vmScheduleFrequency"]') as HTMLSelectElement).value).toBe('daily');
  expect((root.querySelector('[data-test-subj="vmScheduleHour"]') as HTMLSelectElement).value).toBe('2');
  expect(text).toMatch(/Next run: .*\(UTC\)/);
  expect(root.querySelector('[data-test-subj="vmScheduleLastProblem"]')?.textContent).toMatch(/No SNMP credential/);
  ReactDOM.unmountComponentAtNode(root);
});

it('warns about load under a 15-minute schedule and shows a skipped run', async () => {
  mockSchedule = { ...mockSchedule, frequency: '15m', lastRun: { at: '2026-10-13T02:15:00.000Z', status: 'skipped', message: 'previous scan still running' } };
  const root = document.createElement('div');
  await act(async () => {
    ReactDOM.render(<ScheduledScans />, root);
  });
  expect(root.querySelector('[data-test-subj="vmScheduleShortWarning"]')?.textContent).toBe('Short intervals add SNMP and NVD load');
  expect(root.querySelector('[data-test-subj="vmScheduleLast"]')?.textContent).toMatch(/skipped: previous scan still running$/);
  ReactDOM.unmountComponentAtNode(root);
});

it('names the last scan duration in the warning when known', () => {
  expect(shortIntervalWarning(42400)).toBe('Short intervals add SNMP and NVD load; a scan takes about 42 s here');
  expect(shortIntervalWarning(null)).toBe('Short intervals add SNMP and NVD load');
});
