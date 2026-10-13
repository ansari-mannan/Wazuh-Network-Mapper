/**
 * @jest-environment jsdom
 */
import React from 'react';
import ReactDOM from 'react-dom';
import { act } from 'react-dom/test-utils';
import { ScheduleResponse } from '../../../common';

const schedule: ScheduleResponse = {
  frequency: 'daily',
  dailyHour: 2,
  nextRun: '2026-10-14T02:00:00.000Z',
  timeZone: 'UTC',
  lastRun: { at: '2026-10-13T02:00:00.000Z', status: 'failed', message: 'No SNMP credential is set in the dashboard server environment' },
};
jest.mock('../../lib/services', () => ({
  useServices: () => ({ http: { get: async () => schedule }, notifications: {} }),
}));
jest.mock('../../lib/scan', () => ({ useScan: () => ({ scan: null }) }));

import { ScheduledScans } from './ScheduledScans';

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
