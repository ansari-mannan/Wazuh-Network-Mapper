// Scheduled scans: the owner's choice (schedule.json beside the graph, like
// targets.json) and the timer that starts each due scan through the same
// startScan as a manual scan, so the one-at-a-time lock covers both. The file
// holds the choice and the last scheduled run only, never a credential.
import { promises as fs } from 'fs';
import path from 'path';
import { schema } from '@osd/config-schema';
import { ScheduleFile, ScheduleFrequency, ScheduledRun, ScheduleResponse } from '../common';
import { writeFileAtomic } from './fsutil';

export const FREQUENCIES: ScheduleFrequency[] = ['off', '1h', '3h', '6h', '12h', 'daily'];
const EVERY_HOURS: Partial<Record<ScheduleFrequency, number>> = { '1h': 1, '3h': 3, '6h': 6, '12h': 12 };

// POST /api/vulnmapper/schedule's body (the literals are FREQUENCIES).
export const scheduleBody = schema.object({
  frequency: schema.oneOf([
    schema.literal('off'),
    schema.literal('1h'),
    schema.literal('3h'),
    schema.literal('6h'),
    schema.literal('12h'),
    schema.literal('daily'),
  ]),
  dailyHour: schema.number({
    min: 0,
    max: 23,
    validate: (v) => (Number.isInteger(v) ? undefined : 'must be a whole hour'),
  }),
});

export const OFF: ScheduleFile = { frequency: 'off', dailyHour: 2, lastRun: null };

export function scheduleFilePath(graphPath: string): string {
  return path.join(path.dirname(path.resolve(graphPath)), 'schedule.json');
}

/** schedule.json's text (null: no file) as a schedule; anything unreadable is off. */
export function parseSchedule(text: string | null): ScheduleFile {
  let doc: any;
  try {
    doc = text ? JSON.parse(text) : null;
  } catch {
    return OFF;
  }
  if (!doc || typeof doc !== 'object') return OFF;
  const frequency = FREQUENCIES.includes(doc.frequency) ? doc.frequency : 'off';
  const dailyHour = Number.isInteger(doc.dailyHour) && doc.dailyHour >= 0 && doc.dailyHour <= 23 ? doc.dailyHour : OFF.dailyHour;
  const r = doc.lastRun;
  const lastRun =
    r && typeof r.at === 'string' && ['completed', 'failed', 'skipped'].includes(r.status)
      ? { at: r.at, status: r.status, message: typeof r.message === 'string' ? r.message : '' }
      : null;
  return { frequency, dailyHour, lastRun };
}

/**
 * The first due time strictly after `now`, in the server's local time: every
 * N hours runs on the local hours divisible by N (00:00, 03:00, ... for 3h),
 * so the slots do not drift across restarts; daily runs at dailyHour:00.
 */
export function nextRun({ frequency, dailyHour }: Pick<ScheduleFile, 'frequency' | 'dailyHour'>, now: Date): Date | null {
  if (frequency === 'off') return null;
  const t = new Date(now);
  t.setMinutes(0, 0, 0);
  const every = EVERY_HOURS[frequency];
  for (let i = 0; i < 49; i++) {
    t.setHours(t.getHours() + (i ? 1 : 0));
    if (t <= now) continue;
    if (every ? t.getHours() % every === 0 : t.getHours() === dailyHour) return t;
  }
  return null; // unreachable: every frequency has a slot within 48 hours
}

/** Whether the server environment holds an SNMP credential the scanner reads. */
export function hasEnvCredential(env: NodeJS.ProcessEnv): boolean {
  return ['VULNMAPPER_SNMP_COMMUNITY', 'SNMP_COMMUNITIES', 'SNMP_COMMUNITY', 'SNMP_V3_USER'].some((k) => (env[k] || '').trim() !== '');
}

export const NO_CREDENTIAL =
  'No SNMP credential is set in the dashboard server environment (SNMP_COMMUNITIES, SNMP_COMMUNITY ' +
  'or SNMP_V3_USER). Scheduled scans use only that, never one typed into the scan form.';

export interface SchedulerDeps {
  file: string;
  /** start a scheduled scan (startScan); false if a scan is already running */
  startScan: (onDone: (ok: boolean, message: string) => void) => boolean;
  hasCredential: () => boolean;
  logger: { info: (m: string) => void; warn: (m: string) => void };
  now?: () => Date;
}

export function createScheduler(deps: SchedulerDeps) {
  const now = deps.now || (() => new Date());
  let state: ScheduleFile = OFF;
  let timer: NodeJS.Timeout | null = null;
  let due: Date | null = null;
  let writing: Promise<void> = Promise.resolve();

  // Writes are chained so two never share the temp file.
  const save = () => {
    const text = JSON.stringify(state, null, 2);
    writing = writing
      .then(async () => {
        await writeFileAtomic(deps.file, text);
      })
      .catch((e) => deps.logger.warn(`could not save ${deps.file}: ${(e as Error).message}`));
    return writing;
  };

  const record = (status: ScheduledRun['status'], message: string, at: Date) => {
    state = { ...state, lastRun: { at: at.toISOString(), status, message } };
    save();
  };

  const arm = (after: Date) => {
    if (timer) clearTimeout(timer);
    timer = null;
    due = nextRun(state, after);
    if (!due) return;
    const slot = due;
    timer = setTimeout(() => fire(slot), Math.max(0, slot.getTime() - now().getTime()));
  };

  const fire = (slot: Date) => {
    const at = now();
    if (!deps.hasCredential()) {
      deps.logger.warn(`scheduled scan not started: ${NO_CREDENTIAL}`);
      record('failed', NO_CREDENTIAL, at);
    } else if (
      !deps.startScan((ok, message) => {
        if (ok) deps.logger.info('scheduled scan completed');
        record(ok ? 'completed' : 'failed', message, at);
      })
    ) {
      deps.logger.info(`scheduled scan for ${slot.toISOString()} skipped: a scan was already running`);
      record('skipped', 'A scan was already running, so this slot was skipped.', at);
    } else {
      deps.logger.info(`scheduled scan started (slot ${slot.toISOString()})`);
    }
    // a timer can fire a moment early: never pick the same slot again
    arm(new Date(Math.max(at.getTime(), slot.getTime())));
  };

  return {
    /** Read schedule.json and arm the timer (plugin start). */
    async load() {
      let text: string | null = null;
      try {
        text = await fs.readFile(deps.file, 'utf8');
      } catch {
        // no schedule yet: off
      }
      state = parseSchedule(text);
      arm(now());
      if (due) deps.logger.info(`scheduled scans: ${state.frequency}, next at ${due.toISOString()}`);
    },
    /** Save a new choice and re-arm. The last run is kept. */
    async set(choice: Pick<ScheduleFile, 'frequency' | 'dailyHour'>) {
      state = { ...state, frequency: choice.frequency, dailyHour: choice.dailyHour };
      arm(now());
      await save();
    },
    get(): ScheduleResponse {
      return {
        ...state,
        nextRun: due ? due.toISOString() : null,
        timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      };
    },
    stop() {
      if (timer) clearTimeout(timer);
      timer = null;
    },
  };
}

export type Scheduler = ReturnType<typeof createScheduler>;
