// Whether the UI should re-read the graph: the liveness route reports the
// graph file's modified time, and an automatic scan changes it. Each new file
// time is tried once, so a graph that cannot be read does not loop.
export function shouldReloadGraph(
  graphMtime: string | null | undefined,
  shownFileTime: string | null,
  lastTried: string | null
): boolean {
  return Boolean(graphMtime) && graphMtime !== shownFileTime && graphMtime !== lastTried;
}
