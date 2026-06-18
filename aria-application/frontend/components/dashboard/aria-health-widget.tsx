"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import type { AriaAlertStats } from "@/lib/api";

interface AriaHealthWidgetProps {
  stats?: AriaAlertStats;
  error?: boolean;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;

const SEVERITY_CLASS: Record<string, string> = {
  critical: "text-destructive bg-destructive/10",
  high: "text-warning bg-warning/10",
  medium: "text-primary bg-primary/10",
  low: "text-muted-foreground bg-muted",
};

export function AriaHealthWidget({ stats, error }: AriaHealthWidgetProps) {
  if (error) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <AlertTriangle className="h-3.5 w-3.5 text-warning" />
            ARIA Health
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <p className="text-sm text-muted-foreground">Unable to load internal alerts.</p>
        </CardContent>
      </Card>
    );
  }

  const unacknowledged = stats?.unacknowledged ?? 0;
  const bySeverity = stats?.by_severity ?? {};

  if (unacknowledged === 0) {
    return (
      <Card className="border-success/20">
        <CardContent className="p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-success/10">
              <ShieldCheck className="h-4 w-4 text-success" />
            </div>
            <div>
              <p className="text-sm font-medium">ARIA Health</p>
              <p className="text-xs text-muted-foreground">All systems operational</p>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-warning/30">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <AlertTriangle className="h-3.5 w-3.5 text-warning" />
          ARIA Health
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-0 space-y-2">
        <div className="flex items-baseline gap-2">
          <span className="text-xl font-bold">{unacknowledged}</span>
          <span className="text-xs text-muted-foreground">unacknowledged internal alert{unacknowledged !== 1 ? "s" : ""}</span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {SEVERITY_ORDER.map((sev) => {
            const count = bySeverity[sev] ?? 0;
            if (count === 0) return null;
            return (
              <span
                key={sev}
                className={cn(
                  "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium",
                  SEVERITY_CLASS[sev] ?? "text-muted-foreground bg-muted"
                )}
              >
                {sev.charAt(0).toUpperCase() + sev.slice(1)}: {count}
              </span>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
