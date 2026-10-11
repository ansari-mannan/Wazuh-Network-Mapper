import React, { createContext, ReactNode, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { VulnerabilitiesDoc } from '../../common';
import { useServices } from './services';

// The full per-asset CVE list, shared by the vulnerability report. Loaded once
// on mount; `reload` re-reads it (after a scan). A missing file comes back as a
// doc with metadata.state 'absent' (the server's clean "not available" state).
interface VulnerabilitiesState {
  doc: VulnerabilitiesDoc | null;
  loading: boolean;
  error: string | null;
  reload: () => Promise<void>;
}

const VulnerabilitiesContext = createContext<VulnerabilitiesState | null>(null);

export function VulnerabilitiesProvider({ children }: { children: ReactNode }) {
  const { http } = useServices();
  const [doc, setDoc] = useState<VulnerabilitiesDoc | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setDoc(await http.get<VulnerabilitiesDoc>('/api/vulnmapper/vulnerabilities'));
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
  return <VulnerabilitiesContext.Provider value={value}>{children}</VulnerabilitiesContext.Provider>;
}

export function useVulnerabilities(): VulnerabilitiesState {
  const state = useContext(VulnerabilitiesContext);
  if (!state) throw new Error('useVulnerabilities must be used inside VulnerabilitiesProvider');
  return state;
}
