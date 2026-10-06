import React, { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { LivenessResponse } from '../../common';
import { useServices } from './services';

interface LivenessContextValue {
  liveness: LivenessResponse | null;
}

const LivenessContext = createContext<LivenessContextValue | null>(null);

export function LivenessProvider({ children }: { children: ReactNode }) {
  const { http } = useServices();
  const [liveness, setLiveness] = useState<LivenessResponse | null>(null);

  const fetchLiveness = useCallback(async () => {
    try {
      setLiveness(await http.get<LivenessResponse>('/api/vulnmapper/liveness'));
    } catch (e) {
      // keep last known
    }
  }, [http]);

  useEffect(() => {
    if (!liveness?.enabled) return;

    // Poll based on interval or default to 5s if not specified (backend default is 20s)
    const interval = (liveness.intervalSeconds || 5) * 1000;

    // Simple window visibility check
    const intervalId = window.setInterval(() => {
        if (document.hidden) return;
        fetchLiveness();
    }, interval);

    fetchLiveness();
    return () => clearInterval(intervalId);
  }, [liveness?.enabled, liveness?.intervalSeconds, fetchLiveness]);

  return <LivenessContext.Provider value={{ liveness }}>{children}</LivenessContext.Provider>;
}

export function useLiveness(): LivenessContextValue {
  const value = useContext(LivenessContext);
  if (!value) throw new Error('useLiveness must be used inside LivenessProvider');
  return value;
}
