// The scan in progress, shared by every page: started from the scan settings,
// polled (often while one runs, slowly otherwise, so a scheduled or automatic
// scan is followed too), the graph reloaded when it succeeds.
import React, { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { ActiveChecks, ScanState } from '../../common';
import { useServices } from './services';
import { useGraph } from './graph';
import { nvdToastLine } from './nvdText';

const POLL_MS = 1500;
const IDLE_POLL_MS = 15000; // only while the tab is visible

// Scan state shared by the whole app, so a scan started on the settings page
// is still followed (and the graph reloaded when it succeeds) if the user
// moves to another page while it runs.
interface ScanContextValue {
  scan: ScanState | null;
  /** start a scan; the community is sent once with this request only. replaceEmpty swaps
   * the map in even when the crawl polled no device. */
  start: (community: string, checks?: ScanChoices) => Promise<void>;
}

// The scan form's switches: the active checks, and two that change only how the scan is kept or reused.
// preempt: stop a running automatic or scheduled scan first.
type ScanChoices = Partial<ActiveChecks> & { replaceEmpty?: boolean; freshServiceScan?: boolean; preempt?: boolean };

/**
 * "An automatic scan is running (stage: …, 42 s in)" when an automatic or
 * scheduled scan runs, which Run scan may stop; null otherwise (a manual scan
 * is never stopped). Pure.
 */
export function backgroundScanText(scan: ScanState | null, now: number): string | null {
  if (scan?.status !== 'running' || (scan.trigger !== 'automatic' && scan.trigger !== 'scheduled')) return null;
  const started = scan.startedAt ? Date.parse(scan.startedAt) : NaN;
  const seconds = Number.isNaN(started) ? null : Math.max(0, Math.round((now - started) / 1000));
  const kind = scan.trigger === 'automatic' ? 'An automatic' : 'A scheduled';
  const stage = scan.stage || 'starting';
  return `${kind} scan is running (stage: ${stage}${seconds === null ? '' : `, ${seconds} s in`})`;
}

const ScanContext = createContext<ScanContextValue | null>(null);

/**
 * The toast for a scan that just ended, or null. A failure always gets one; a
 * success only when someone pressed Run scan: an automatic or scheduled one is
 * quiet, and the page refreshes by itself.
 */
export function scanEndToast(
  scan: ScanState,
  nvdLine: (apiKey: ScanState['nvdKey']) => string | undefined = nvdToastLine
): { kind: 'success' | 'danger'; title: string; text?: string } | null {
  if (scan.status === 'failed') {
    return { kind: 'danger', title: 'Scan failed; the previous graph is still shown', text: scan.message || undefined };
  }
  if (scan.trigger === 'automatic' || scan.trigger === 'scheduled') return null;
  return { kind: 'success', title: 'Scan completed; graph updated', text: nvdLine(scan.nvdKey) };
}

export function ScanProvider({ children }: { children: ReactNode }) {
  const { http, notifications } = useServices();
  const { reload } = useGraph();
  const [scan, setScan] = useState<ScanState | null>(null);
  const previous = useRef<ScanState | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      setScan(await http.get<ScanState>('/api/vulnmapper/scan/status'));
    } catch (e) {
      // keep the last known state; the next poll tries again
    }
  }, [http]);

  // React to a scan finishing: success -> reload the graph everywhere.
  useEffect(() => {
    const before = previous.current;
    previous.current = scan;
    if (!before || before.status !== 'running' || !scan || scan.status === 'running') return;
    const toast = scanEndToast(scan);
    if (toast?.kind === 'danger') notifications.toasts.addDanger({ title: toast.title, text: toast.text });
    if (toast?.kind === 'success') notifications.toasts.addSuccess({ title: toast.title, text: toast.text });
    if (scan.status !== 'failed') reload();
  }, [scan, notifications, reload]);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  // Fast while a scan runs; slowly while idle (tab visible), so a scan this
  // browser did not start shows its progress, its toast and the new graph.
  // refining: the scores change once more after the scan (FileWatcher re-reads the files)
  const running = scan?.status === 'running' || Boolean(scan?.refining);
  useEffect(() => {
    const poll = () => {
      if (running || !document.hidden) fetchStatus();
    };
    const timer = window.setInterval(poll, running ? POLL_MS : IDLE_POLL_MS);
    return () => window.clearInterval(timer);
  }, [running, fetchStatus]);

  const start = useCallback(
    async (community: string, checks: ScanChoices = {}) => {
      try {
        const body = { ...(community ? { community } : {}), ...checks };
        setScan(await http.post<ScanState>('/api/vulnmapper/scan', { body: JSON.stringify(body) }));
      } catch (e) {
        notifications.toasts.addDanger({
          title: 'Could not start the scan',
          text: e.body?.message || e.message,
        });
        fetchStatus();
      }
    },
    [http, notifications, fetchStatus]
  );

  return <ScanContext.Provider value={{ scan, start }}>{children}</ScanContext.Provider>;
}

export function useScan(): ScanContextValue {
  const value = useContext(ScanContext);
  if (!value) throw new Error('useScan must be used inside ScanProvider');
  return value;
}
