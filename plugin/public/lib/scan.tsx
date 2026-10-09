import React, { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { ScanState } from '../../common';
import { useServices } from './services';
import { useGraph } from './graph';

const POLL_MS = 1500;

// Scan state shared by the whole app, so a scan started on the settings page
// is still followed (and the graph reloaded when it succeeds) if the user
// moves to another page while it runs.
interface ScanContextValue {
  scan: ScanState | null;
  /** start a scan; the community is sent once with this request only */
  start: (community: string, options?: { checkDefaultCommunities?: boolean }) => Promise<void>;
}

const ScanContext = createContext<ScanContextValue | null>(null);

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
    if (scan.status === 'failed') {
      notifications.toasts.addDanger({
        title: 'Scan failed; the previous graph is still shown',
        text: scan.message || undefined,
      });
    } else {
      notifications.toasts.addSuccess('Scan completed; graph updated');
      reload();
    }
  }, [scan, notifications, reload]);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  // Poll only while a scan is running.
  useEffect(() => {
    if (scan?.status !== 'running') return;
    const timer = window.setInterval(fetchStatus, POLL_MS);
    return () => window.clearInterval(timer);
  }, [scan?.status, fetchStatus]);

  const start = useCallback(
    async (community: string, options: { checkDefaultCommunities?: boolean } = {}) => {
      try {
        const body = {
          ...(community ? { community } : {}),
          ...(options.checkDefaultCommunities !== undefined
            ? { checkDefaultCommunities: options.checkDefaultCommunities }
            : {}),
        };
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
