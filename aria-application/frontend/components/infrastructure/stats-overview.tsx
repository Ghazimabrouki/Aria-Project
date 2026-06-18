"use client";

import { Cpu, MemoryStick, Database, Network, HardDrive, AlertCircle, CheckCircle2, XCircle, Clock, Play } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

interface StatsOverviewProps {
  stats?: {
    total: number;
    by_status: Record<string, number>;
  } | null;
  isLoading?: boolean;
}

const statusMeta = [
  { key: "diagnosing", label: "Diagnosing", icon: Clock, color: "text-primary bg-primary/10 border-primary/20" },
  { key: "findings_ready", label: "Findings Ready", icon: AlertCircle, color: "text-warning bg-warning/10 border-warning/20" },
  { key: "acknowledged", label: "Acknowledged", icon: CheckCircle2, color: "text-emerald-500 bg-emerald-500/10 border-emerald-500/20" },
  { key: "escalated", label: "Escalated", icon: XCircle, color: "text-destructive bg-destructive/10 border-destructive/20" },
];

export function StatsOverview({ stats, isLoading }: StatsOverviewProps) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-20 w-full" />
        ))}
      </div>
    );
  }

  const total = stats?.total ?? 0;

  return (
    <div className="space-y-3">
      {/* Total + breakdown */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {statusMeta.map((meta) => {
          const count = stats?.by_status?.[meta.key] ?? 0;
          const Icon = meta.icon;
          const pct = total > 0 ? Math.round((count / total) * 100) : 0;
          return (
            <Card key={meta.key} className="overflow-hidden">
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className={cn("flex h-8 w-8 items-center justify-center rounded-md border", meta.color)}>
                    <Icon className="h-4 w-4" />
                  </div>
                  <span className="text-2xl font-bold tabular-nums">{count}</span>
                </div>
                <div className="text-xs text-muted-foreground mb-1.5">{meta.label}</div>
                <div className="h-1 w-full rounded-full bg-muted overflow-hidden">
                  <div
                    className={cn("h-full rounded-full transition-all", meta.color.split(" ")[1])}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

export function ResourceTypeBreakdown({
  investigations,
}: {
  investigations: Array<{ resource_type?: string }>;
}) {
  const counts = investigations.reduce((acc, inv) => {
    const type = inv.resource_type || "unknown";
    acc[type] = (acc[type] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const types = [
    { key: "cpu", label: "CPU", icon: Cpu, color: "text-blue-500 bg-blue-500/10 border-blue-500/20" },
    { key: "memory", label: "Memory", icon: MemoryStick, color: "text-purple-500 bg-purple-500/10 border-purple-500/20" },
    { key: "disk", label: "Disk", icon: Database, color: "text-amber-500 bg-amber-500/10 border-amber-500/20" },
    { key: "network", label: "Network", icon: Network, color: "text-emerald-500 bg-emerald-500/10 border-emerald-500/20" },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      {types.map((type) => {
        const Icon = type.icon;
        const count = counts[type.key] ?? 0;
        return (
          <Card key={type.key} className="overflow-hidden">
            <CardContent className="p-4 flex items-center gap-3">
              <div className={cn("flex h-10 w-10 items-center justify-center rounded-lg border", type.color)}>
                <Icon className="h-5 w-5" />
              </div>
              <div>
                <div className="text-2xl font-bold tabular-nums">{count}</div>
                <div className="text-xs text-muted-foreground">{type.label} Alerts</div>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
