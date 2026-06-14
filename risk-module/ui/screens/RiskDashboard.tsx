"use client";

import { RiskTile } from "../components/RiskTile";

// Phase 6: de-functionalized. The live risk-engine calls are replaced with
// static literals chosen to be internally consistent (Critical Hosts = 4 lines
// up with the 4 red bars in Risk Overview; Attack Paths = 3 matches the 3 cards
// on the Attack Paths page; Total Hosts / Vulns match the Scan Config table).
const TILES = {
  totalHosts: 32,
  vulnerabilitiesFound: 89,
  criticalHosts: 4,
  attackPaths: 3,
};

const RECENT_ALERTS: {
  id: string;
  hostname: string;
  message: string;
  severity: "low" | "medium" | "high" | "critical";
  when: string;
}[] = [
  { id: "a1", hostname: "web-srv-01", message: "Sandbox escape (CVE-2026-8401) detected", severity: "critical", when: "2026-03-19 02:14" },
  { id: "a2", hostname: "db-srv-01", message: "Heap overflow in graphics component (CVE-2025-60724)", severity: "critical", when: "2026-03-19 01:52" },
  { id: "a3", hostname: "app-srv-02", message: "Integer overflow in networking stack (CVE-2026-8956)", severity: "high", when: "2026-03-19 01:30" },
  { id: "a4", hostname: "dc-01", message: "Privilege escalation finding flagged for review", severity: "high", when: "2026-03-18 23:06" },
  { id: "a5", hostname: "file-srv-03", message: "Outdated TLS configuration detected", severity: "medium", when: "2026-03-18 21:44" },
  { id: "a6", hostname: "mail-01", message: "SMTP banner discloses software version", severity: "medium", when: "2026-03-18 19:18" },
];

const RISK_OVERVIEW: { hostname: string; risk: number }[] = [
  { hostname: "web-srv-01", risk: 9.4 },
  { hostname: "db-srv-01", risk: 8.9 },
  { hostname: "dc-01", risk: 8.1 },
  { hostname: "app-srv-02", risk: 7.6 },
  { hostname: "mail-01", risk: 4.6 },
  { hostname: "file-srv-03", risk: 5.2 },
  { hostname: "ws-114", risk: 3.1 },
  { hostname: "print-01", risk: 2.0 },
];

export function RiskDashboard() {
  return (
    <div className="min-h-screen bg-background">
      <main className="mx-auto max-w-7xl px-4 py-8">
        <div className="flex items-baseline justify-between gap-2 mb-6">
          <div>
            <h1 className="text-2xl font-semibold theme-text-primary">Wazuh Vulnerability Mapper</h1>
            <p className="text-sm text-slate-400">Network vulnerability overview</p>
          </div>
          <p className="text-sm text-slate-400">Last scan: 2026-03-19 02:14:33 UTC</p>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-4 mb-6">
          <RiskTile title="Total Hosts" value={TILES.totalHosts} level="low" />
          <RiskTile title="Vulnerabilities Found" value={TILES.vulnerabilitiesFound} level="high" />
          <RiskTile title="Critical Hosts" value={TILES.criticalHosts} level="high" />
          <RiskTile title="Attack Paths" value={TILES.attackPaths} level="medium" />
        </div>

        <div className="grid gap-6 lg:grid-cols-5">
          <section className="lg:col-span-3">
            <h2 className="text-xs uppercase tracking-wider text-slate-400 mb-3">Recent Alerts</h2>
            <div className="space-y-2">
              {RECENT_ALERTS.map((alert, idx) => (
                <div key={alert.id} className={`grid grid-cols-[auto_1fr_auto] items-center gap-3 p-3 rounded-xl ${idx % 2 === 0 ? "theme-tile" : "bg-transparent"}`}>
                  <span className={`${alert.severity === "critical" ? "bg-red-500" : alert.severity === "high" ? "bg-orange-500" : "bg-amber-500"} text-black px-2 py-1 rounded-full text-[11px] uppercase`}>{alert.severity}</span>
                  <div>
                    <div className="theme-text-primary font-semibold">{alert.message}</div>
                    <div className="text-xs text-slate-500">{alert.hostname}</div>
                  </div>
                  <div className="text-xs text-slate-500">{alert.when}</div>
                </div>
              ))}
            </div>
          </section>

          <section className="lg:col-span-2">
            <h2 className="text-xs uppercase tracking-wider text-slate-400 mb-3">Risk Overview</h2>
            <div className="space-y-3">
              {RISK_OVERVIEW.map((asset) => {
                const risk = asset.risk;
                const color = risk > 7 ? "bg-red-500" : risk > 4 ? "bg-amber-500" : "bg-emerald-500";
                return (
                  <div key={asset.hostname} className="flex items-center justify-between gap-3">
                    <div className="w-full">
                      <div className="text-sm theme-text-primary font-semibold">{asset.hostname}</div>
                      <div className="h-2 w-full rounded-full theme-bg-muted mt-1 overflow-hidden">
                        <div className={`${color} h-full`} style={{ width: `${Math.min(100, risk * 10)}%` }} />
                      </div>
                    </div>
                    <div className={`font-bold ${risk > 7 ? "text-red-400" : risk > 4 ? "text-amber-400" : "text-emerald-400"}`}>{risk.toFixed(1)}</div>
                  </div>
                );
              })}
            </div>
          </section>
        </div>

        <div className="mt-6 flex justify-end">
          <button className="bg-blue-600 hover:bg-blue-700 text-white rounded-lg px-6 py-2 font-semibold">Run New Scan</button>
        </div>
      </main>
    </div>
  );
}
