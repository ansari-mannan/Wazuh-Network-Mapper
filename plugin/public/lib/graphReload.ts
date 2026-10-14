// Whether the UI should re-read the graph: the files route reports the graph
// file's modified time, and a scan the browser did not start (scheduled,
// automatic, another analyst's) changes it. Each new file time is tried once,
// so a graph that cannot be read does not loop.
import { FileTimes } from '../../common';

export function shouldReloadGraph(
  graphMtime: string | null | undefined,
  shownFileTime: string | null,
  lastTried: string | null
): boolean {
  return Boolean(graphMtime) && graphMtime !== shownFileTime && graphMtime !== lastTried;
}

/**
 * Which documents to re-read, given the file times seen on the last poll
 * (null: the first poll, which only records them) and now. The graph is
 * compared with the time of the graph shown (shouldReloadGraph); the other two
 * with the last poll, since a rescore or liveness recompute rewrites them
 * without a new scan. Pure.
 */
export function filesToReload(
  prev: FileTimes | null,
  next: FileTimes,
  shownGraphTime: string | null,
  lastTriedGraph: string | null
): { graph: boolean; vulnerabilities: boolean; attackPaths: boolean } {
  return {
    graph: shouldReloadGraph(next.graph, shownGraphTime, lastTriedGraph),
    vulnerabilities: prev !== null && next.vulnerabilities !== prev.vulnerabilities,
    attackPaths: prev !== null && next.attackPaths !== prev.attackPaths,
  };
}
