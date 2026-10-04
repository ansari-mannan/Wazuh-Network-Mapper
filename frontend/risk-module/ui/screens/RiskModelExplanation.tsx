"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function RiskModelExplanation() {
  return (
    <div className="min-h-screen bg-background">
      <main className="mx-auto max-w-3xl px-4 py-8">
        <h1 className="mb-6 text-2xl font-semibold theme-text-primary">Risk Model Explanation</h1>

        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Risk Calculation Formula</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 font-mono text-sm text-slate-300">
            <p>Risk Score = CVSS × Exposure × Criticality</p>
            <p className="mt-2 text-slate-400">Exposure and criticality act as multipliers on the base CVSS score.</p>
          </CardContent>
        </Card>

        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Aggregation Logic</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm text-slate-300">
            <p>Average of top vulnerabilities across asset clusters.</p>
            <p className="text-slate-400">
              For each asset, we take the top N (e.g. 3) vulnerabilities by CVSS and average their adjusted scores (after exposure and criticality multipliers).
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Assumptions</CardTitle>
          </CardHeader>
          <CardContent className="list-inside list-disc space-y-1 text-sm text-slate-300">
            <li>Static topology</li>
            <li>Pre-assigned asset criticality values</li>
            <li>Exposure classification: internet-facing, internal, restricted</li>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
