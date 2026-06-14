"use client";

import { getNetworkLegend } from "@/risk-module/api-layer/riskService";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function TopologyLegend() {
  const legend = getNetworkLegend();

  return (
    <div className="min-h-screen bg-background">
      <main className="mx-auto max-w-7xl px-4 py-8 space-y-6">
        <h1 className="text-2xl font-semibold theme-text-primary">Topology Legend</h1>

        <Card>
          <CardHeader>
            <CardTitle>Network Summary</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p>Total devices: {legend.summary.totalDevices}</p>
            <p>Total VLANs: {legend.summary.totalVlans}</p>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="text-xs uppercase tracking-wider text-slate-400">
                    <th className="p-2">VLAN</th>
                    <th className="p-2">Subnet</th>
                    <th className="p-2">Devices</th>
                  </tr>
                </thead>
                <tbody>
                  {legend.summary.networks.map((network) => (
                    <tr key={`${network.vlan}-${network.subnet}`} className="border-t border-slate-800">
                      <td className="p-2">{network.vlan}</td>
                      <td className="p-2">{network.subnet}</td>
                      <td className="p-2">{network.devices}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Topology Node Legend</CardTitle>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="text-xs uppercase tracking-wider text-slate-400">
                  <th className="p-2">Asset</th>
                  <th className="p-2">Segment</th>
                  <th className="p-2">VLAN</th>
                  <th className="p-2">Subnet</th>
                  <th className="p-2">Exposure</th>
                  <th className="p-2">Criticality</th>
                  <th className="p-2">Risk</th>
                </tr>
              </thead>
              <tbody>
                {legend.nodes.map((node) => (
                  <tr key={node.assetId} className="border-t border-slate-800">
                    <td className="p-2 font-mono">{node.hostname}</td>
                    <td className="p-2">{node.segment}</td>
                    <td className="p-2">{node.vlan}</td>
                    <td className="p-2">{node.subnet}</td>
                    <td className="p-2">{node.exposure}</td>
                    <td className="p-2">{node.criticality}</td>
                    <td className="p-2">{node.risk}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Implementation Note</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-slate-400">
            <p>
              In the final product, this legend should be driven from live topology metadata (VLAN/subnet mapping per node, link classification, discovered networks) instead of hardcoded segment mapping.
            </p>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
