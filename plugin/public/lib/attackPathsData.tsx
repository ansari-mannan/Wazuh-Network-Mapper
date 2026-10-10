import React, { createContext, ReactNode, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { AttackPathsDoc } from '../../common';
import { useServices } from './services';

// Attack-paths document shared by the page and the topology detail panel.
// Loaded once on mount; `reload` re-reads it after a target is marked.
interface AttackPathsState {
  doc: AttackPathsDoc | null;
  loading: boolean;
  error: string | null;
  reload: () => Promise<void>;
}

const AttackPathsContext = createContext<AttackPathsState | null>(null);

export function AttackPathsProvider({ children }: { children: ReactNode }) {
  const { http } = useServices();
  const [doc, setDoc] = useState<AttackPathsDoc | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setDoc(await http.get<AttackPathsDoc>('/api/vulnmapper/attack-paths'));
    } catch (e) {
      setError(e.body?.message || e.message);
    } finally {
      setLoading(false);
    }
  }, [http]);

  useEffect(() => {
    reload();
  }, [reload]);

  const value = useMemo(() => ({ doc, loading, error, reload }), [doc, loading, error, reload]);
  return <AttackPathsContext.Provider value={value}>{children}</AttackPathsContext.Provider>;
}

export function useAttackPaths(): AttackPathsState {
  const state = useContext(AttackPathsContext);
  if (!state) throw new Error('useAttackPaths must be used inside AttackPathsProvider');
  return state;
}
