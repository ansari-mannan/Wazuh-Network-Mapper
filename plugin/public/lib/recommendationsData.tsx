import React, { createContext, ReactNode, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { RecommendationStatus, RecommendationsFile } from '../../common';
import { useServices } from './services';

// The shared recommendations tracker, loaded once on mount. setStatus posts one
// item's status and refreshes from the server's returned file. A missing file
// comes back as { statuses: {} }.
interface RecommendationsState {
  file: RecommendationsFile | null;
  loading: boolean;
  error: string | null;
  reload: () => Promise<void>;
  setStatus: (key: string, status: RecommendationStatus) => Promise<void>;
}

const RecommendationsContext = createContext<RecommendationsState | null>(null);

export function RecommendationsProvider({ children }: { children: ReactNode }) {
  const { http } = useServices();
  const [file, setFile] = useState<RecommendationsFile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setFile(await http.get<RecommendationsFile>('/api/vulnmapper/recommendations'));
    } catch (e) {
      setError(e.body?.message || e.message);
    } finally {
      setLoading(false);
    }
  }, [http]);

  const setStatus = useCallback(
    async (key: string, status: RecommendationStatus) => {
      setFile(await http.post<RecommendationsFile>('/api/vulnmapper/recommendations/status', { body: JSON.stringify({ key, status }) }));
    },
    [http]
  );

  useEffect(() => {
    reload();
  }, [reload]);

  const value = useMemo(() => ({ file, loading, error, reload, setStatus }), [file, loading, error, reload, setStatus]);
  return <RecommendationsContext.Provider value={value}>{children}</RecommendationsContext.Provider>;
}

export function useRecommendations(): RecommendationsState {
  const state = useContext(RecommendationsContext);
  if (!state) throw new Error('useRecommendations must be used inside RecommendationsProvider');
  return state;
}
