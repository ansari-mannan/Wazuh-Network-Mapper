"use client";

import { cn } from "@/lib/utils";

type RiskLevel = "low" | "medium" | "high";

function getRiskLevel(value: number): RiskLevel {
  if (value >= 7.5) return "high";
  if (value >= 4) return "medium";
  return "low";
}

const levelStyles: Record<RiskLevel, string> = {
  low: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/30",
  medium: "bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30",
  high: "bg-red-500/15 text-red-700 dark:text-red-400 border-red-500/30",
};

interface RiskTileProps {
  title: string;
  value: string | number;
  level?: RiskLevel | "auto";
  className?: string;
}

export function RiskTile({ title, value, level = "auto", className }: RiskTileProps) {
  const resolvedLevel =
    level === "auto" && typeof value === "number"
      ? getRiskLevel(value)
      : level === "auto"
        ? "medium"
        : level;
  return (
    <div
      className={cn(
        "rounded-lg border p-4 transition-shadow hover:shadow-md",
        levelStyles[resolvedLevel],
        className
      )}
    >
      <p className="text-xs font-medium uppercase tracking-wider opacity-90">
        {title}
      </p>
      <p className="mt-1 text-2xl font-bold">{value}</p>
    </div>
  );
}
