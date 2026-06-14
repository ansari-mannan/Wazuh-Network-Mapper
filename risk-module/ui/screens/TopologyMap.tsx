"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { RefreshCw } from "lucide-react";
import { getGraph, type GraphResponse } from "@/lib/vulnmapperApi";
import PocTopologyView from "../poc/PocTopologyView";
import "../poc/poc-theme.css";

// Topology Map: the POC topology view wired to the real backend graph. The page
// header / sidebar chrome comes from the dashboard layout; only the canvas area
// itself uses the POC's minimalist light theme (scoped under `.poc-scope`).
export function TopologyMap() {
  const router = useRouter();
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

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

  // Load the current graph on first mount so the canvas isn't empty.
  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  // Node IDs contain colons (e.g. "device:00:23:ac:e5:74:00"), so the id MUST be
  // encodeURIComponent-ed here and decodeURIComponent-ed in the asset page.
  const handleSelect = useCallback(
    (nodeId: string) => {
      router.push(`/dashboard/asset/${encodeURIComponent(nodeId)}`);
    },
    [router],
  );

  const counts = graph?.metadata?.counts;

  return (
    <div className="min-h-screen bg-background">
      <main className="mx-auto max-w-7xl px-4 py-8">
        <div className="flex items-center justify-between gap-3 mb-2">
          <h1 className="text-2xl font-semibold theme-text-primary">Network Topology</h1>
          <button
            onClick={loadGraph}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-sm font-medium text-foreground hover:opacity-80 disabled:opacity-50"
          >
            <RefreshCw size={15} className={loading ? "animate-spin" : ""} /> Load Graph
          </button>
        </div>

        {counts && !loadError && (
          <p className="text-sm text-slate-400 mb-3">
            {counts.nodes} nodes · {counts.devices} devices · {counts.endpoints} endpoints ·{" "}
            {counts.lldp_edges + counts.endpoint_edges} edges · {counts.unparented_endpoints} unparented
          </p>
        )}
        {loadError && (
          <p className="text-sm text-red-400 mb-3">load failed: {loadError}</p>
        )}

        <div className="theme-card rounded-xl border p-2 h-[720px] relative overflow-hidden">
          <div className="poc-scope" style={{ width: "100%", height: "100%", borderRadius: 10 }}>
            <PocTopologyView graph={graph} onSelect={handleSelect} />
          </div>
        </div>
      </main>
    </div>
  );
}
