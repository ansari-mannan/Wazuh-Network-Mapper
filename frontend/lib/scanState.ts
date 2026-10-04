/**
 * Module-level shared scan state.
 *
 * Ported from the in-memory `scan` object in the POC's `gui/backend/server.js`.
 * A `let` at module scope persists across requests within the same Next.js
 * server process, so both `app/api/scan/route.ts` (the writer) and
 * `app/api/scan/status/route.ts` (the reader) see the same object. A POC runs
 * one scan at a time, so a single object is enough; a real deployment would key
 * this by job id.
 */
export type ScanStatus = "idle" | "running" | "done" | "error";

export type ScanState = {
  status: ScanStatus;
  error: string | null;
  startedAt: string | null;
  finishedAt: string | null;
};

let scan: ScanState = {
  status: "idle",
  error: null,
  startedAt: null,
  finishedAt: null,
};

export function getScan(): ScanState {
  return scan;
}

export function setScan(next: ScanState): void {
  scan = next;
}
