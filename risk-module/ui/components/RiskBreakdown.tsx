"use client";

import { cn } from "@/lib/utils";

export type VulnItem = { cveId: string; cvss: number; title?: string };

interface RiskBreakdownProps {
  title?: string;
  items: VulnItem[];
  className?: string;
}

function severityClass(cvss: number): string {
  if (cvss >= 9) return "bg-red-500/20 text-red-700 dark:text-red-400";
  if (cvss >= 7) return "bg-amber-500/20 text-amber-700 dark:text-amber-400";
  return "bg-emerald-500/20 text-emerald-700 dark:text-emerald-400";
}

export function RiskBreakdown({
  title = "Top Vulnerabilities",
  items,
  className,
}: RiskBreakdownProps) {
  return (
    <div className={cn("space-y-2", className)}>
      {title ? <h3 className="text-sm font-semibold">{title}</h3> : null}
      <ul className="space-y-2">
        {items.map((item, i) => (
          <li
            key={item.cveId}
            className={cn(
              "flex items-center justify-between rounded-md border px-3 py-2 text-sm",
              severityClass(item.cvss)
            )}
          >
            <span>
              {i + 1}. {item.cveId}
              {item.title && (
                <span className="ml-2 text-muted-foreground">{item.title}</span>
              )}
            </span>
            <span className="font-mono font-semibold">{item.cvss}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
