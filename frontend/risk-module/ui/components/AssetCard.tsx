"use client";

import Link from "next/link";
import { cn } from "@/lib/utils";

interface AssetCardProps {
  hostname: string;
  risk: number;
  assetId: string;
  exposure?: string;
  className?: string;
}

function riskColor(risk: number): string {
  if (risk >= 7.5) return "border-red-500/50 bg-red-500/5";
  if (risk >= 4) return "border-amber-500/50 bg-amber-500/5";
  return "border-emerald-500/50 bg-emerald-500/5";
}

export function AssetCard({
  hostname,
  risk,
  assetId,
  exposure,
  className,
}: AssetCardProps) {
  return (
    <Link href={`/dashboard/asset/${assetId}`}>
      <div
        className={cn(
          "rounded-lg border p-4 transition-shadow hover:shadow-md",
          riskColor(risk),
          className
        )}
      >
        <div className="flex items-center justify-between">
          <span className="font-medium">{hostname}</span>
          <span className="text-lg font-bold">{risk.toFixed(1)}</span>
        </div>
        {exposure && (
          <p className="mt-1 text-xs text-muted-foreground">{exposure}</p>
        )}
      </div>
    </Link>
  );
}
