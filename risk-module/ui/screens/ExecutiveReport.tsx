"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FileJson, FileText } from "lucide-react";

// Phase 6: de-functionalized. Static executive summary values. The disabled
// JSON/PDF export buttons and the placeholder caption are left as-is — they are
// already correctly framed as not-yet-built.
const TOTAL_ENVIRONMENT_RISK = 7.4;

const TOP_HIGH_RISK_ASSETS: { hostname: string; risk: number }[] = [
  { hostname: "web-srv-01", risk: 9.4 },
  { hostname: "db-srv-01", risk: 8.9 },
  { hostname: "dc-01", risk: 8.1 },
  { hostname: "app-srv-02", risk: 7.6 },
  { hostname: "file-srv-03", risk: 5.2 },
];

export function ExecutiveReport() {
  return (
    <div className="min-h-screen bg-background">
      <main className="mx-auto max-w-3xl px-4 py-8">
        <h1 className="text-2xl font-semibold theme-text-primary mb-6">Executive Report</h1>

        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Executive Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">Total Environment Risk: {TOTAL_ENVIRONMENT_RISK}</p>
          </CardContent>
        </Card>

        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Top 5 High-Risk Assets</CardTitle>
          </CardHeader>
          <CardContent>
            <ol className="list-inside list-decimal space-y-2 text-sm">
              {TOP_HIGH_RISK_ASSETS.map((a) => (
                <li key={a.hostname}>{a.hostname} — <span className="font-mono font-semibold">{a.risk}</span></li>
              ))}
            </ol>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Export Options</CardTitle>
          </CardHeader>
          <CardContent className="flex gap-2">
            <button className="rounded-lg border border-slate-700 px-3 py-1 text-sm" disabled>
              <FileJson className="inline-block mr-1" /> JSON
            </button>
            <button className="rounded-lg border border-slate-700 px-3 py-1 text-sm" disabled>
              <FileText className="inline-block mr-1" /> PDF
            </button>
            <p className="self-center text-xs text-slate-400">(Placeholder — not functional in MVP)</p>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
