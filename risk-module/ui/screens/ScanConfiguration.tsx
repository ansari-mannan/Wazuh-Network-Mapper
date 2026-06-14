"use client";

import { useState } from "react";
import { getScanConfigDefaults } from "@/risk-module/api-layer/riskService";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

// The real, working scan lives on the Topology Map page. Everything here is
// decorative local state — the selects, the community field and the "Start Scan"
// button look active but do nothing.
export function ScanConfiguration() {
  const defaults = getScanConfigDefaults();
  const [schedule, setSchedule] = useState(defaults.schedule);
  const [scanType, setScanType] = useState(defaults.scanType);
  const [community, setCommunity] = useState("cyfor123");

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
                <select className="theme-input w-full p-2 text-foreground" value={scanType} onChange={(e) => setScanType(e.target.value)}>
                  <option>Network Devices Scan</option>
                  <option>Endpoints Scan</option>
                  <option>Full Scan</option>
                </select>
              </div>

              <div>
                <div className="text-sm text-slate-400 mb-1">Schedule</div>
                <select className="theme-input w-full p-2 text-foreground" value={schedule} onChange={(e) => setSchedule(e.target.value)}>
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
                  aria-label="SNMP community string"
                />
              </div>

              {/* Looks like a primary action, but is inert. */}
              <button className="w-full rounded-lg bg-blue-600 p-3 text-white font-semibold hover:bg-blue-700">Start Scan</button>
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
