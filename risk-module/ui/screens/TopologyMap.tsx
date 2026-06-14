"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { RefreshCw, Radar } from "lucide-react";
import {
  getConfig,
  getGraph,
  startScan,
  getScanStatus,
  type GraphResponse,
} from "@/lib/vulnmapperApi";
import PocTopologyView from "../poc/PocTopologyView";
import "../poc/poc-theme.css";

// Topology Map: the POC topology view wired to the real backend graph. This is
// also where the REAL scan lives (ported from the POC's App.jsx/Toolbar): a
// community input + "Run New Scan" that hits /api/scan, polls /api/scan/status,
// and reloads the graph on success. The page header / sidebar chrome comes from
// the dashboard layout; only the canvas area uses the POC's light theme.
type ScanUiState = "idle" | "running" | "done" | "error";

export function TopologyMap() {
  const router = useRouter();
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const [community, setCommunity] = useState("");
  const [scanState, setScanState] = useState<ScanUiState>("idle");
  const [scanError, setScanError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadGraph = useCallback(async () => {
    setLoadError(null);
    setLoading(true);
    try {
      setGraph(await getGraph());
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  // Pre-fill the community input from the backend default, and load the current
  // graph on first mount so the canvas isn't empty.
  useEffect(() => {
    getConfig()
      .then((c) => setCommunity(c.community))
      .catch(() => {});
    loadGraph();
  }, [loadGraph]);

  // Clear the poll timer on unmount.
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const runScan = useCallback(async () => {
    if (scanState === "running") return;
    setScanError(null);
    setScanState("running");
    try {
      await startScan(community);
    } catch (e) {
      setScanState("error");
      setScanError(e instanceof Error ? e.message : String(e));
      return; // existing graph stays on screen
    }
    // Poll status until the async scan finishes. On success refetch the graph;
    // on error surface the message and KEEP the currently displayed graph.
    pollRef.current = setInterval(async () => {
      try {
        const s = await getScanStatus();
        if (s.status === "done") {
          if (pollRef.current) clearInterval(pollRef.current);
          await loadGraph();
          setScanState("done");
          setTimeout(() => setScanState("idle"), 2500);
        } else if (s.status === "error") {
          if (pollRef.current) clearInterval(pollRef.current);
          setScanState("error");
          setScanError(s.error || "scan failed");
        }
      } catch (e) {
        if (pollRef.current) clearInterval(pollRef.current);
        setScanState("error");
        setScanError(e instanceof Error ? e.message : String(e));
      }
    }, 1000);
  }, [community, loadGraph, scanState]);

  // Node IDs contain colons (e.g. "device:00:23:ac:e5:74:00"), so the id MUST be
  // encodeURIComponent-ed here and decodeURIComponent-ed in the asset page.
  const handleSelect = useCallback(
    (nodeId: string) => {
      router.push(`/dashboard/asset/${encodeURIComponent(nodeId)}`);
    },
    [router],
  );

  const counts = graph?.metadata?.counts;
  const scanning = scanState === "running";

  return (
    <div className="min-h-screen bg-background">
      <main className="mx-auto max-w-7xl px-4 py-8">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
          <h1 className="text-2xl font-semibold theme-text-primary">Network Topology</h1>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={loadGraph}
              disabled={loading || scanning}
              className="inline-flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-sm font-medium text-foreground hover:opacity-80 disabled:opacity-50"
            >
              <RefreshCw size={15} className={loading ? "animate-spin" : ""} /> Load Graph
            </button>

            <input
              className="theme-input rounded-lg px-3 py-2 text-sm text-foreground w-36"
              value={community}
              onChange={(e) => setCommunity(e.target.value)}
              placeholder="community"
              disabled={scanning}
              aria-label="SNMP community string"
            />
            <button
              onClick={runScan}
              disabled={scanning}
              className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-sm font-semibold text-white hover:bg-blue-700 disabled:opacity-60"
            >
              <Radar size={15} className={scanning ? "animate-spin" : ""} />
              {scanState === "running" ? "Scanning…" : scanState === "done" ? "Scan complete" : "Run New Scan"}
            </button>
          </div>
        </div>

        {/* Status / counts strip — kept inline so the graph never disappears. */}
        <div className="flex flex-wrap items-center gap-2 mb-3 text-sm min-h-[20px]">
          {counts && !loadError && (
            <span className="text-slate-400">
              {counts.nodes} nodes · {counts.devices} devices · {counts.endpoints} endpoints ·{" "}
              {counts.lldp_edges + counts.endpoint_edges} edges · {counts.unparented_endpoints} unparented
            </span>
          )}
          {scanState === "done" && (
            <span className="rounded-full bg-emerald-500/15 text-emerald-400 px-2 py-0.5 text-xs">scan complete</span>
          )}
          {loadError && (
            <span className="rounded-full bg-red-500/15 text-red-400 px-2 py-0.5 text-xs">load failed: {loadError}</span>
          )}
          {scanError && (
            <span className="rounded-full bg-red-500/15 text-red-400 px-2 py-0.5 text-xs break-words max-w-full">scan failed: {scanError}</span>
          )}
        </div>

        <div className="theme-card rounded-xl border p-2 h-[720px] relative overflow-hidden">
          <div className="poc-scope" style={{ width: "100%", height: "100%", borderRadius: 10 }}>
            <PocTopologyView graph={graph} onSelect={handleSelect} />
          </div>
        </div>
      </main>
    </div>
  );
}
