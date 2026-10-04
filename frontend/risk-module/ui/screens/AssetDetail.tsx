"use client";

import { useEffect, useMemo, useState } from "react";
import { getGraph, type GraphResponse, type GraphNode } from "@/lib/vulnmapperApi";
import PocDeviceDetail from "../poc/PocDeviceDetail";
import "../poc/poc-theme.css";

interface AssetDetailProps {
  assetId: string;
}

// Asset / Device Detail: the POC device-detail view wired to the real backend
// graph. Node IDs contain colons, so the route param was encodeURIComponent-ed
// in the Topology page and must be decodeURIComponent-ed here before lookup.
export function AssetDetail({ assetId }: AssetDetailProps) {
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Recover the real node_id. Next.js already decodes route params, but the spec
  // mandates an explicit decode; it is a no-op on already-decoded ids (which only
  // contain letters/digits/colons, never % escapes), so it is safe either way.
  const decodedId = useMemo(() => {
    try {
      return decodeURIComponent(assetId);
    } catch {
      return assetId;
    }
  }, [assetId]);

  useEffect(() => {
    let cancelled = false;
    getGraph()
      .then((g) => {
        if (!cancelled) setGraph(g);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const node: GraphNode | undefined = graph?.nodes.find((n) => n.node_id === decodedId);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-slate-400">Loading…</p>
      </div>
    );
  }

  // Calm empty state — the expected path when something links to a mock asset id
  // (e.g. web-srv-01) that has no matching real graph node.
  if (error || !node) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <p className="text-slate-400">Asset not found.</p>
          {error && <p className="text-xs text-slate-500 mt-2">{error}</p>}
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <main className="mx-auto max-w-4xl px-4 py-8">
        <div className="poc-scope" style={{ borderRadius: 12, padding: 4 }}>
          <PocDeviceDetail node={node} />
        </div>
      </main>
    </div>
  );
}
