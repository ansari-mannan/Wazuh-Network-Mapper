import React, { createContext, ReactNode, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { LivenessResponse } from '../../common';
import { useGraph } from './graph';
import { shouldReloadGraph } from './graphReload';
import { useServices } from './services';

// Liveness state from GET /api/vulnmapper/liveness. Fetched once on mount (that
// is how the UI learns whether liveness is enabled at all); after that it is
// polled every intervalSeconds, but only while enabled and the tab is visible.
// Liveness changes alone never reload the graph or re-lay it out; the graph is
// reloaded only when the graph file itself changed (an automatic scan).

interface LivenessContextValue {
  /** null until the first fetch answers; enabled false when the feature is off */
  liveness: LivenessResponse | null;
}

const LivenessContext = createContext<LivenessContextValue | null>(null);

export function LivenessProvider({ children }: { children: ReactNode }) {
  const { http } = useServices();
  const [liveness, setLiveness] = useState<LivenessResponse | null>(null);

  const fetchLiveness = useCallback(async () => {
    try {
      const next = await http.get<LivenessResponse>('/api/vulnmapper/liveness');
      // The file only changes once per pass: keep the old object (and spare
      // every map node a re-render) when nothing new arrived.
      setLiveness((prev) =>
        prev &&
        prev.enabled === next.enabled &&
        prev.intervalSeconds === next.intervalSeconds &&
        prev.checkedAt === next.checkedAt &&
        prev.graphMtime === next.graphMtime
          ? prev
          : next
      );
    } catch (e) {
      // keep the last known state
    }
  }, [http]);

  // Once on mount, whatever the state.
  useEffect(() => {
    fetchLiveness();
  }, [fetchLiveness]);

  const enabled = Boolean(liveness?.enabled);
  const seconds = liveness?.intervalSeconds || 0;
  useEffect(() => {
    if (!enabled || seconds <= 0) return;
    const poll = () => {
      if (!document.hidden) fetchLiveness();
    };
    const id = window.setInterval(poll, seconds * 1000);
    // Catch up as soon as the tab is shown again.
    document.addEventListener('visibilitychange', poll);
    return () => {
      window.clearInterval(id);
      document.removeEventListener('visibilitychange', poll);
    };
  }, [enabled, seconds, fetchLiveness]);

  // An automatic scan rewrote the graph file: show the new graph.
  const { fileTime, loading, reload } = useGraph();
  const lastTried = useRef<string | null>(null);
  const graphMtime = enabled ? liveness?.graphMtime : null;
  useEffect(() => {
    if (loading || !shouldReloadGraph(graphMtime, fileTime, lastTried.current)) return;
    lastTried.current = graphMtime || null;
    reload();
  }, [graphMtime, fileTime, loading, reload]);

  const value = useMemo(() => ({ liveness }), [liveness]);
  return <LivenessContext.Provider value={value}>{children}</LivenessContext.Provider>;
}

export function useLiveness(): LivenessContextValue {
  const value = useContext(LivenessContext);
  if (!value) throw new Error('useLiveness must be used inside LivenessProvider');
  return value;
}
