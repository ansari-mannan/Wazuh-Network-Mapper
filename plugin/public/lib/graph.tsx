import React, { createContext, ReactNode, useCallback, useContext, useEffect, useState } from 'react';
import { GraphResponse } from '../../common';
import { useServices } from './services';

// Graph data shared by every page. Loaded once on mount; `reload` re-reads the
// file (after a scan, or from the topology toolbar).
interface GraphState {
  graph: GraphResponse | null;
  /** last-modified time of the graph file on the server (ISO string) */
  fileTime: string | null;
  loading: boolean;
  error: string | null;
  reload: () => Promise<void>;
}

const GraphContext = createContext<GraphState | null>(null);

export function GraphProvider({ children }: { children: ReactNode }) {
  const { http } = useServices();
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [fileTime, setFileTime] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await http.fetch<GraphResponse>('/api/vulnmapper/graph', { asResponse: true });
      setGraph(res.body || null);
      setFileTime(res.response?.headers.get('x-vulnmapper-graph-mtime') || null);
    } catch (e) {
      setError(e.body?.message || e.message);
    } finally {
      setLoading(false);
    }
  }, [http]);

  useEffect(() => {
    reload();
  }, [reload]);

  return (
    <GraphContext.Provider value={{ graph, fileTime, loading, error, reload }}>
      {children}
    </GraphContext.Provider>
  );
}

export function useGraph(): GraphState {
  const state = useContext(GraphContext);
  if (!state) throw new Error('useGraph must be used inside GraphProvider');
  return state;
}
