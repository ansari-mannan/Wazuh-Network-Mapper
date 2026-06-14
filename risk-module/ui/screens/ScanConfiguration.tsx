"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { getScanConfigDefaults } from "@/risk-module/api-layer/riskService";
import { getConfig, startScan, getScanStatus } from "@/lib/vulnmapperApi";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

// Cosmetic stage labels cycled while a scan runs. We do NOT claim a specific
// stage is literally executing (the attack-path stage isn't implemented), so a
// generic "Scan in progress…" is shown as the real status line.
const stages = ["Discovering hosts…", "Scanning ports…", "Mapping CVEs…", "Assembling graph…"];

type ScanUiState = "idle" | "running" | "done" | "error";

export function ScanConfiguration() {
  const defaults = getScanConfigDefaults();
  // Schedule + Scan Type are decorative local state only (no backend effect).
  const [schedule, setSchedule] = useState(defaults.schedule);
  const [scanType, setScanType] = useState(defaults.scanType);

  // Real, wired-up state.
  const [community, setCommunity] = useState("");
  const [scanState, setScanState] = useState<ScanUiState>("idle");
  const [scanError, setScanError] = useState<string | null>(null);
  const [stageIdx, setStageIdx] = useState(0);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const stageRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Prefill the community input from the backend default (mirrors the POC's
  // App.jsx useEffect).
  useEffect(() => {
    getConfig()
      .then((c) => setCommunity(c.community))
      .catch(() => {});
  }, []);

  // Clear timers on unmount.
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
      if (stageRef.current) clearInterval(stageRef.current);
    };
  }, []);

  const stopTimers = () => {
    if (pollRef.current) clearInterval(pollRef.current);
    if (stageRef.current) clearInterval(stageRef.current);
    pollRef.current = null;
    stageRef.current = null;
  };

  const startScanFlow = async () => {
    if (scanState === "running") return;
    setScanError(null);
    setScanState("running");
    setStageIdx(0);

    try {
      await startScan(community);
    } catch (e) {
      setScanState("error");
      setScanError(e instanceof Error ? e.message : String(e));
      return;
    }

    // Cosmetic stage cycling (purely visual progress motion).
    stageRef.current = setInterval(() => {
      setStageIdx((p) => (p + 1) % stages.length);
    }, 1200);

    // Real polling of the backend scan status.
    pollRef.current = setInterval(async () => {
      try {
        const s = await getScanStatus();
        if (s.status === "done") {
          stopTimers();
          setScanState("done");
        } else if (s.status === "error") {
          stopTimers();
          setScanState("error");
          setScanError(s.error || "scan failed");
        }
      } catch (e) {
        stopTimers();
        setScanState("error");
        setScanError(e instanceof Error ? e.message : String(e));
      }
    }, 1000);
  };

  const running = scanState === "running";

  return (
    <div className="min-h-screen bg-background">
      <main className="mx-auto max-w-7xl px-4 py-8">
        <h1 className="text-2xl font-semibold theme-text-primary mb-2">Scan Configuration</h1>
        <div className="grid gap-6 xl:grid-cols-[55%_45%]">
          <Card className="p-4">
            <CardHeader>
              <CardTitle>Scan Settings</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <div className="text-sm text-slate-400 mb-1">Scan Type</div>
                <select className="theme-input w-full p-2 text-foreground" value={scanType} onChange={(e) => setScanType(e.target.value)} disabled={running}>
                  <option>Network Devices Scan</option>
                  <option>Endpoints Scan</option>
                  <option>Full Scan</option>
                </select>
              </div>

              <div>
                <div className="text-sm text-slate-400 mb-1">Schedule</div>
                <select className="theme-input w-full p-2 text-foreground" value={schedule} onChange={(e) => setSchedule(e.target.value)} disabled={running}>
                  <option>Daily</option>
                  <option>Weekly</option>
                  <option>Monthly</option>
                </select>
              </div>

              <div>
                <div className="text-sm text-slate-400 mb-1">SNMP Community String</div>
                <input
                  className="theme-input w-full p-2 text-foreground"
                  value={community}
                  onChange={(e) => setCommunity(e.target.value)}
                  placeholder="community"
                  disabled={running}
                  aria-label="SNMP community string"
                />
              </div>

              {running ? (
                <div>
                  <div className="h-3 w-full rounded-full theme-bg-muted overflow-hidden">
                    <div className="h-full bg-gradient-to-r from-sky-500 to-violet-500 animate-pulse" style={{ width: "100%" }} />
                  </div>
                  <p className="text-sm text-slate-400 mt-2">Scan in progress… ({stages[stageIdx]})</p>
                </div>
              ) : (
                <button onClick={startScanFlow} className="w-full rounded-lg bg-blue-600 p-3 text-white font-semibold hover:bg-blue-700">Start Scan</button>
              )}

              {scanState === "done" && (
                <div className="rounded-lg border border-emerald-600/40 bg-emerald-500/10 p-3 text-sm">
                  <p className="text-emerald-400 font-semibold">Scan complete.</p>
                  <Link href="/dashboard/topology" className="text-sky-400 underline">View updated topology →</Link>
                </div>
              )}

              {scanState === "error" && scanError && (
                <div className="rounded-lg border border-red-600/40 bg-red-500/10 p-3 text-sm">
                  <p className="text-red-400 font-semibold">Scan failed</p>
                  <p className="text-slate-400 break-words mt-1 max-h-32 overflow-y-auto whitespace-pre-wrap">{scanError}</p>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="p-4">
            <CardHeader>
              <CardTitle>Previous Scans</CardTitle>
            </CardHeader>
            <CardContent>
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-slate-400 text-xs uppercase tracking-wide">
                    <th className="p-1">Timestamp</th>
                    <th className="p-1">Hosts</th>
                    <th className="p-1">Vulns</th>
                    <th className="p-1">Status</th>
                    <th className="p-1">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {[{
                    id: 1, timestamp: "2026-03-19 02:14:33", hosts: 32, vulns: 89, status: "Completed"
                  }, {
                    id: 2, timestamp: "2026-03-18 23:06:12", hosts: 31, vulns: 90, status: "Completed"
                  }, {
                    id: 3, timestamp: "2026-03-18 03:40:01", hosts: 32, vulns: 87, status: "Failed"
                  }].map((scan) => (
                    <tr key={scan.id} className="border-t border-slate-800">
                      <td className="p-1">{scan.timestamp}</td>
                      <td className="p-1">{scan.hosts}</td>
                      <td className="p-1">{scan.vulns}</td>
                      <td className="p-1"><span className={`px-2 py-1 rounded-full text-xs ${scan.status === "Completed" ? "bg-emerald-500 text-black" : "bg-amber-500 text-black"}`}>{scan.status}</span></td>
                      <td className="p-1"><a href="#" className="text-sky-400">View Logs</a></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}
