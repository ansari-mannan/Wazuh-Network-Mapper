// Follow changes made outside this browser: every IDLE_POLL_MS while the tab is
// visible, ask the server for the files' modified times and re-read whichever
// document changed (filesToReload). A scheduled or automatic scan, a rescore
// started by another analyst and a liveness recompute all reach an open page.
import { useEffect, useRef } from 'react';
import { FileTimes } from '../../common';
import { useAttackPaths } from './attackPathsData';
import { useGraph } from './graph';
import { filesToReload } from './graphReload';
import { useServices } from './services';
import { useVulnerabilities } from './vulnerabilities';

export const IDLE_POLL_MS = 15000;

export function FileWatcher() {
  const { http } = useServices();
  const { fileTime, loading, reload: reloadGraph } = useGraph();
  const { reload: reloadPaths } = useAttackPaths();
  const { reload: reloadVulns } = useVulnerabilities();
  const seen = useRef<FileTimes | null>(null);
  const lastTried = useRef<string | null>(null);
  // the latest values, for the timer's callback
  const live = useRef({ fileTime, loading, reloadGraph, reloadPaths, reloadVulns });
  live.current = { fileTime, loading, reloadGraph, reloadPaths, reloadVulns };

  useEffect(() => {
    const poll = async () => {
      if (document.hidden || live.current.loading) return;
      let next: FileTimes;
      try {
        next = await http.get<FileTimes>('/api/vulnmapper/files');
      } catch {
        return; // the next poll tries again
      }
      const todo = filesToReload(seen.current, next, live.current.fileTime, lastTried.current);
      seen.current = next;
      if (todo.graph) {
        lastTried.current = next.graph;
        live.current.reloadGraph();
      }
      if (todo.vulnerabilities) live.current.reloadVulns();
      if (todo.attackPaths) live.current.reloadPaths();
    };
    poll();
    const id = window.setInterval(poll, IDLE_POLL_MS);
    document.addEventListener('visibilitychange', poll);
    return () => {
      window.clearInterval(id);
      document.removeEventListener('visibilitychange', poll);
    };
  }, [http]);

  return null;
}
