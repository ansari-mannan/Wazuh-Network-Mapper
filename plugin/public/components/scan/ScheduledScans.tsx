// Scheduled scans: how often the server scans on its own, when it next will,
// and how the last scheduled scan went. Times are the dashboard server's.
import React, { useCallback, useEffect, useState } from 'react';
import { EuiCallOut, EuiFormRow, EuiPanel, EuiSelect, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { ScheduleFrequency, ScheduleResponse } from '../../../common';
import { useServices } from '../../lib/services';
import { useScan } from '../../lib/scan';

const FREQUENCY_OPTIONS: Array<{ value: ScheduleFrequency; text: string }> = [
  { value: 'off', text: 'Off' },
  { value: '15m', text: 'Every 15 minutes' },
  { value: '30m', text: 'Every 30 minutes' },
  { value: '1h', text: 'Every hour' },
  { value: '3h', text: 'Every 3 hours' },
  { value: '6h', text: 'Every 6 hours' },
  { value: '12h', text: 'Every 12 hours' },
  { value: 'daily', text: 'Daily at…' },
];

const HOUR_OPTIONS = Array.from({ length: 24 }, (_, h) => ({ value: h, text: `${String(h).padStart(2, '0')}:00` }));

const RUN_WORDS = { completed: 'Completed', failed: 'Failed', skipped: 'Skipped' };

/** An ISO time in the server's time zone, with the zone named. */
export const serverTime = (iso: string, timeZone: string) =>
  `${new Date(iso).toLocaleString(undefined, { timeZone })} (${timeZone})`;

/** The warning under the selector for a 15- or 30-minute schedule; durationMs is the last scan's, if known. */
export function shortIntervalWarning(durationMs: number | null): string {
  const took = durationMs !== null && durationMs >= 0 ? `; a scan takes about ${Math.round(durationMs / 1000)} s here` : '';
  return `Short intervals add SNMP and NVD load${took}`;
}

const errorText = (e: any) => e?.body?.message || e?.message || String(e);

export function ScheduledScans() {
  const { http, notifications } = useServices();
  const { scan } = useScan();
  const [schedule, setSchedule] = useState<ScheduleResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setSchedule(await http.get<ScheduleResponse>('/api/vulnmapper/schedule'));
      setError(null);
    } catch (e) {
      setError(errorText(e));
    }
  }, [http]);

  // reload when a scan starts or ends, so the last scheduled run is current
  useEffect(() => {
    load();
  }, [load, scan?.status]);

  const save = async (frequency: ScheduleFrequency, dailyHour: number) => {
    try {
      setSchedule(
        await http.post<ScheduleResponse>('/api/vulnmapper/schedule', { body: JSON.stringify({ frequency, dailyHour }) })
      );
    } catch (e) {
      notifications.toasts.addDanger({ title: 'Could not save the schedule', text: errorText(e) });
    }
  };

  const last = schedule?.lastRun;
  const lastDuration =
    scan?.status !== 'running' && scan?.startedAt && scan?.finishedAt
      ? Date.parse(scan.finishedAt) - Date.parse(scan.startedAt)
      : null;
  return (
    <EuiPanel paddingSize="m" data-test-subj="vmSchedule">
      <EuiTitle size="xs">
        <h2>Scheduled scans</h2>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiText size="xs" color="subdued">
        <p>
          Scheduled scans run with every active check off and take the SNMP credential from the dashboard
          server&apos;s environment (SNMP_COMMUNITIES or SNMP_COMMUNITY), never from this form.
        </p>
      </EuiText>
      <EuiSpacer size="m" />
      {error && <EuiCallOut size="s" color="danger" iconType="alert" title={error} />}
      {schedule && (
        <>
          <EuiFormRow
            label="Scan automatically"
            helpText={
              (schedule.frequency === '15m' || schedule.frequency === '30m') && (
                <span data-test-subj="vmScheduleShortWarning">{shortIntervalWarning(lastDuration)}</span>
              )
            }
          >
            <EuiSelect
              options={FREQUENCY_OPTIONS}
              value={schedule.frequency}
              onChange={(e) => save(e.target.value as ScheduleFrequency, schedule.dailyHour)}
              data-test-subj="vmScheduleFrequency"
            />
          </EuiFormRow>
          {schedule.frequency === 'daily' && (
            <EuiFormRow label={`Hour (${schedule.timeZone})`}>
              <EuiSelect
                options={HOUR_OPTIONS}
                value={schedule.dailyHour}
                onChange={(e) => save('daily', Number(e.target.value))}
                data-test-subj="vmScheduleHour"
              />
            </EuiFormRow>
          )}
          <EuiSpacer size="s" />
          <EuiText size="s">
            <p data-test-subj="vmScheduleNext">
              Next run: {schedule.nextRun ? serverTime(schedule.nextRun, schedule.timeZone) : 'none scheduled'}
            </p>
            <p data-test-subj="vmScheduleLast">
              Last scheduled scan:{' '}
              {last
                ? `${serverTime(last.at, schedule.timeZone)}, ${RUN_WORDS[last.status].toLowerCase()}${
                    last.status === 'skipped' ? `: ${last.message}` : ''
                  }`
                : 'none yet'}
            </p>
          </EuiText>
          {last && last.status === 'failed' && (
            <EuiCallOut
              size="s"
              color="danger"
              iconType="alert"
              title={`Last scheduled scan ${RUN_WORDS[last.status].toLowerCase()}`}
              data-test-subj="vmScheduleLastProblem"
            >
              <p>{last.message}</p>
            </EuiCallOut>
          )}
        </>
      )}
    </EuiPanel>
  );
}
