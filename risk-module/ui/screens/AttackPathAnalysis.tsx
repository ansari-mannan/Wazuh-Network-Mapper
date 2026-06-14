"use client";

import { useState } from "react";
import { getTopologyForUI, getAssetsWithRisk } from "@/risk-module/api-layer/riskService";
import { TopologyGraph } from "../components/TopologyGraph";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

// Phase 6: de-functionalized. The CVSS-weighted Dijkstra/A* path-ranking engine
// described in the project plan is NOT implemented. The paths below are written
// as static literals; the click-to-select interaction is harmless local UI
// state, not a real engine. The Path Topology graph keeps rendering the (mock)
// topology, and the Timeline / Risk Narrative panels render off the selected
// hardcoded path, same as before.

type AttackPath = { path: string[]; score: number; narrative: string };

const PATHS: AttackPath[] = [
  {
    path: ["web-srv-01", "app-srv-02", "db-srv-01"],
    score: 27.4,
    narrative: "Foothold on the internet-facing web server pivots to the application tier, then to the database holding regulated data.",
  },
  {
    path: ["web-srv-01", "file-srv-03", "dc-01"],
    score: 22.7,
    narrative: "Lateral movement from the web server through a shared file server to the domain controller via cached credentials.",
  },
  {
    path: ["mail-01", "dc-01"],
    score: 16.7,
    narrative: "Phishing-delivered code execution on the mail relay enables a direct hop to the domain controller.",
  },
];

export function AttackPathAnalysis() {
  const [selectedPathIndex, setSelectedPathIndex] = useState(0);

  const topology = getTopologyForUI();
  const assets = getAssetsWithRisk();
  const riskMap = Object.fromEntries(assets.map((asset) => [asset.id, asset.aggregatedRisk]));

  const selectedPath = PATHS[selectedPathIndex] ?? null;

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <div className="px-4 py-8">
        <h1 className="text-2xl font-semibold theme-text-primary mb-6">Attack Paths</h1>
      </div>

      <main className="flex-1 px-4 pb-8 grid grid-cols-[300px_1fr] gap-6 overflow-hidden">
        {/* Left Sidebar - Attack Paths List */}
        <div className="overflow-y-auto space-y-3 pr-2">
          {PATHS.map((path, index) => (
            <div
              key={`path-${index}`}
              className={`rounded-xl border p-3 cursor-pointer transition-all ${path === selectedPath ? "theme-card border-2 border-blue-500 shadow-lg bg-blue-50 dark:bg-blue-950" : "theme-tile hover:theme-card-hover"}`}
              onClick={() => setSelectedPathIndex(index)}
            >
              <div className="flex items-center justify-between">
                <p className="theme-text-primary font-semibold text-sm">Path #{index + 1}</p>
                <p className="text-lg font-bold text-red-400">{path.score}</p>
              </div>
              <p className="theme-text-muted text-xs">{path.path.length} steps</p>
            </div>
          ))}
        </div>

        {/* Right Main Content Area */}
        <div className="flex flex-col gap-6 overflow-hidden">
          {/* Path Topology */}
          <Card className="flex-1 overflow-hidden flex flex-col">
            <CardHeader>
              <CardTitle>Path Topology</CardTitle>
            </CardHeader>
            <CardContent className="flex-1 p-0 overflow-hidden">
              <TopologyGraph nodes={topology.nodes} edges={topology.edges} nodeRisk={riskMap} />
            </CardContent>
          </Card>

          {/* Timeline and Risk Narrative */}
          <div className="grid grid-cols-2 gap-6 h-[280px]">
            <Card className="overflow-hidden flex flex-col">
              <CardHeader>
                <CardTitle className="text-sm">Timeline</CardTitle>
              </CardHeader>
              <CardContent className="flex-1 overflow-y-auto relative">
                <div className="absolute left-0 top-0 h-full w-px bg-red-500" />
                <div className="flex flex-col gap-3 pl-4">
                  {selectedPath?.path.map((nodeId, index) => (
                    <div key={`${nodeId}-${index}`} className="relative">
                      <div className="absolute left-[-6px] top-2 h-3 w-3 rounded-full bg-red-400" />
                      <div className="rounded-lg theme-tile p-2">
                        <p className="text-xs font-bold theme-text-primary break-words">{index + 1}. {nodeId}</p>
                        <p className="text-xs theme-text-muted">Compromise detected</p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card className="overflow-hidden flex flex-col">
              <CardHeader>
                <CardTitle className="text-sm">Risk Narrative</CardTitle>
              </CardHeader>
              <CardContent className="flex-1 overflow-y-auto">
                <p className="theme-text-secondary text-xs leading-relaxed">
                  {selectedPath
                    ? `${selectedPath.narrative} Cumulative risk ${selectedPath.score} indicates urgent remediation is required.`
                    : "Select an attack path to view narrative."}
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
}
