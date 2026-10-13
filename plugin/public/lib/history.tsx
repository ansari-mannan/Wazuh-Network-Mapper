// The scan history from the server (server/history.ts): the index, refreshed
// when a scan ends, and one scan's files with the previous scan's.
import { useCallback, useEffect, useState } from 'react';
import { HistoryChangesResponse, HistoryEntry } from '../../common';
import { useServices } from './services';
import { useScan } from './scan';

export function useHistoryIndex() {
  const { http } = useServices();
  const { scan } = useScan();
  const [index, setIndex] = useState<HistoryEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    try {
      setIndex(await http.get<HistoryEntry[]>('/api/vulnmapper/history'));
      setError(null);
    } catch (e: any) {
      setError(e?.body?.message || e?.message || String(e));
    }
  }, [http]);
  // a finished scan adds an entry
  useEffect(() => {
    load();
  }, [load, scan?.status]);
  return { index, error };
}

export function useHistoryChanges(id: string | null) {
  const { http } = useServices();
  const [data, setData] = useState<HistoryChangesResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    setData(null);
    setError(null);
    if (!id) return;
    http
      .get<HistoryChangesResponse>(`/api/vulnmapper/history/${encodeURIComponent(id)}/changes`)
      .then((d) => live && setData(d))
      .catch((e: any) => live && setError(e?.body?.message || e?.message || String(e)));
    return () => {
      live = false;
    };
  }, [http, id]);
  return { data, error };
}
