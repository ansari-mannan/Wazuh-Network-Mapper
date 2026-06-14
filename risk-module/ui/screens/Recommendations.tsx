"use client";

// Phase 6: de-functionalized. Filter pills render ("All" stays active) but are
// inert. "Mark Resolved"/"Reopen" buttons render but do nothing — status never
// changes, so the header counts stay consistent with the static list below.

type Recommendation = {
  id: string;
  assetHostname: string;
  recommendation: string;
  priority: 1 | 2 | 3;
  rationale: string;
  status: "open" | "resolved";
  effort: "High" | "Medium" | "Low";
};

const RECOMMENDATIONS: Recommendation[] = [
  { id: "r1", assetHostname: "web-srv-01", recommendation: "Patch CVE-2026-8401 on web-srv-01 (9.8 CVSS, CRITICAL)", priority: 1, rationale: "Address the critical sandbox-escape finding for CVE-2026-8401.", status: "open", effort: "High" },
  { id: "r2", assetHostname: "db-srv-01", recommendation: "Patch CVE-2025-60724 on db-srv-01 (9.8 CVSS, CRITICAL)", priority: 1, rationale: "Address the critical graphics-component overflow on the database host.", status: "open", effort: "High" },
  { id: "r3", assetHostname: "dc-01", recommendation: "Patch CVE-2026-33824 on dc-01 (9.8 CVSS, CRITICAL)", priority: 1, rationale: "Domain controller exposure to an IKE double-free must be closed first.", status: "open", effort: "High" },
  { id: "r4", assetHostname: "web-srv-01", recommendation: "Patch CVE-2026-8956 on web-srv-01 (9.6 CVSS, CRITICAL)", priority: 1, rationale: "Networking JAR integer overflow on an internet-facing host.", status: "resolved", effort: "High" },
  { id: "r5", assetHostname: "app-srv-02", recommendation: "Patch CVE-2026-8953 on app-srv-02 (8.8 CVSS, HIGH)", priority: 2, rationale: "Use-after-free in accessibility APIs; remediate promptly.", status: "open", effort: "Medium" },
  { id: "r6", assetHostname: "dc-01", recommendation: "Patch CVE-2007-4559 on dc-01 (7.8 CVSS, HIGH)", priority: 2, rationale: "Legacy Python tarfile traversal still present in tooling image.", status: "open", effort: "Medium" },
  { id: "r7", assetHostname: "mail-01", recommendation: "Patch CVE-2024-21413 on mail-01 (7.5 CVSS, HIGH)", priority: 2, rationale: "Outlook RCE reachable from the mail relay.", status: "resolved", effort: "Medium" },
  { id: "r8", assetHostname: "file-srv-03", recommendation: "Patch CVE-2022-3602 on file-srv-03 (5.9 CVSS, MEDIUM)", priority: 3, rationale: "OpenSSL X.509 overflow; schedule in the next maintenance window.", status: "open", effort: "Low" },
  { id: "r9", assetHostname: "ws-114", recommendation: "Patch CVE-2019-11043 on ws-114 (3.1 CVSS, LOW)", priority: 3, rationale: "Low-severity PHP-FPM issue; track for hygiene.", status: "resolved", effort: "Low" },
];

const FILTER = "All"; // visually active; clicking other pills is inert

export function Recommendations() {
  const items = [...RECOMMENDATIONS].sort((a, b) => a.priority - b.priority);
  const resolvedCount = RECOMMENDATIONS.filter((i) => i.status === "resolved").length;
  const openCount = RECOMMENDATIONS.filter((i) => i.status === "open").length;

  return (
    <div className="min-h-screen bg-background">
      <main className="mx-auto max-w-7xl px-4 py-8">
        <div className="flex items-center justify-between mb-4 gap-4">
          <h1 className="text-2xl font-semibold theme-text-primary">Recommendations</h1>
          <div className="text-sm text-slate-400">{openCount} open · {resolvedCount} resolved</div>
        </div>

        <div className="mb-4 space-x-2">
          {["All", "Open", "Resolved"].map((term) => (
            <button
              key={term}
              className={`px-3 py-1 rounded-full text-xs font-semibold ${FILTER === term ? "bg-blue-600 text-white" : "theme-bg-muted theme-text-muted"}`}
            >
              {term}
            </button>
          ))}
        </div>

        <div className="space-y-3">
          {items.map((rec) => {
            const priorityColor = rec.priority === 1 ? "#ef4444" : rec.priority === 2 ? "#f97316" : "#facc15";
            const effortColor = rec.effort === "Low" ? "#22c55e" : rec.effort === "Medium" ? "#f59e0b" : "#ef4444";
            const resolved = rec.status === "resolved";
            return (
              <div key={rec.id} className={`theme-card p-4 ${resolved ? "opacity-40" : ""}`} style={{ borderLeft: `4px solid ${resolved ? "#374151" : priorityColor}` }}>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-1 rounded-full text-xs font-semibold" style={{ background: priorityColor, color: "#000" }}>P{rec.priority}</span>
                      <span className={`text-base font-bold ${resolved ? "line-through" : ""}`}>{rec.recommendation}</span>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-1">
                      <span className="theme-bg-muted px-2 py-1 text-xs text-sky-300 rounded-full">{rec.assetHostname}</span>
                    </div>
                    <p className="mt-2 text-sm text-slate-400">{rec.rationale}</p>
                  </div>
                  <button className="px-3 py-1 rounded-full text-xs font-semibold" style={{ background: effortColor, color: "#000" }}>{rec.status === "open" ? "Mark Resolved" : "Reopen"}</button>
                </div>
              </div>
            );
          })}
        </div>
      </main>
    </div>
  );
}
