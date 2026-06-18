"use client";

import { cn } from "@/lib/utils";

interface SeverityBadgeProps {
  severity: string | number;
  className?: string;
}

const severityConfig: Record<string, { label: string; className: string }> = {
  critical: {
    label: "Critical",
    className: "bg-destructive/10 text-destructive border-destructive/30",
  },
  high: {
    label: "High",
    className: "bg-chart-4/10 text-chart-4 border-chart-4/30",
  },
  medium: {
    label: "Medium",
    className: "bg-warning/10 text-warning border-warning/30",
  },
  low: {
    label: "Low",
    className: "bg-success/10 text-success border-success/30",
  },
};

// Map numeric levels (from Wazuh/alerts) to severity
function getLevelSeverity(level: number): string {
  if (level >= 10) return "critical";
  if (level >= 7) return "high";
  if (level >= 4) return "medium";
  return "low";
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const severityKey = typeof severity === "number"
    ? getLevelSeverity(severity)
    : typeof severity === "string"
    ? severity.toLowerCase()
    : "low";

  const config = severityConfig[severityKey] || severityConfig.low;

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium",
        config.className,
        className
      )}
    >
      {config.label}
    </span>
  );
}
