"use client";

import { Cpu, MemoryStick, Database, Network, HardDrive, TrendingUp, TrendingDown, Minus } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface ResourceGaugeProps {
  type?: string;
  value?: number;
  threshold?: number;
  unit?: string;
  trend?: string;
  baselineDeviation?: string;
  severity?: string;
}

export function ResourceGauge({
  type,
  value = 0,
  threshold = 100,
  unit = "%",
  trend,
  baselineDeviation,
  severity,
}: ResourceGaugeProps) {
  const pct = Math.min(100, Math.max(0, (value / threshold) * 100));

  const colorClass =
    pct >= 100
      ? "text-destructive"
      : pct >= 80
      ? "text-warning"
      : pct >= 60
      ? "text-chart-4"
      : "text-success";

  const bgClass =
    pct >= 100
      ? "bg-destructive"
      : pct >= 80
      ? "bg-warning"
      : pct >= 60
      ? "bg-chart-4"
      : "bg-success";

  const circumference = 2 * Math.PI * 40;
  const strokeDashoffset = circumference - (pct / 100) * circumference;

  const TrendIcon =
    trend === "spike"
      ? TrendingUp
      : trend === "gradual"
      ? TrendingUp
      : trend === "persistent"
      ? TrendingUp
      : trend === "temporary"
      ? TrendingDown
      : Minus;

  return (
    <Card className="overflow-hidden">
      <CardContent className="p-6">
        <div className="flex items-center gap-6">
          {/* SVG Gauge */}
          <div className="relative flex-shrink-0">
            <svg width="100" height="100" viewBox="0 0 100 100" className="-rotate-90">
              <circle
                cx="50"
                cy="50"
                r="40"
                fill="none"
                stroke="currentColor"
                strokeWidth="8"
                className="text-muted/30"
              />
              <circle
                cx="50"
                cy="50"
                r="40"
                fill="none"
                stroke="currentColor"
                strokeWidth="8"
                strokeLinecap="round"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                className={cn("transition-all duration-1000", colorClass)}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className={cn("text-xl font-bold tabular-nums", colorClass)}>
                {value.toFixed(1)}
              </span>
              <span className="text-xs text-muted-foreground">{unit}</span>
            </div>
          </div>

          {/* Details */}
          <div className="flex-1 space-y-2">
            <div className="flex items-center gap-2">
              <ResourceTypeIcon type={type} className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium capitalize">{type || "Resource"}</span>
              {severity && (
                <span
                  className={cn(
                    "text-xs uppercase tracking-wider font-semibold px-1.5 py-0.5 rounded",
                    severity === "critical" && "bg-destructive/10 text-destructive",
                    severity === "high" && "bg-chart-4/10 text-chart-4",
                    severity === "medium" && "bg-warning/10 text-warning",
                    severity === "low" && "bg-success/10 text-success"
                  )}
                >
                  {severity}
                </span>
              )}
            </div>

            <div className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-muted-foreground">Threshold</span>
                <span className="font-medium tabular-nums">
                  {threshold.toFixed(1)} {unit}
                </span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
                <div
                  className={cn("h-full rounded-full transition-all duration-1000", bgClass)}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>

            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              {trend && (
                <span className="flex items-center gap-1">
                  <TrendIcon className="h-3 w-3" />
                  <span className="capitalize">{trend.replace("_", " ")}</span>
                </span>
              )}
              {baselineDeviation && (
                <span className="tabular-nums">{baselineDeviation}</span>
              )}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export function ResourceTypeIcon({
  type,
  className,
}: {
  type?: string;
  className?: string;
}) {
  switch (type?.toLowerCase()) {
    case "cpu":
      return <Cpu className={className} />;
    case "memory":
      return <MemoryStick className={className} />;
    case "disk":
      return <Database className={className} />;
    case "network":
      return <Network className={className} />;
    default:
      return <HardDrive className={className} />;
  }
}

export function ResourceColor(type?: string) {
  switch (type?.toLowerCase()) {
    case "cpu":
      return "text-blue-500 bg-blue-500/10 border-blue-500/20";
    case "memory":
      return "text-purple-500 bg-purple-500/10 border-purple-500/20";
    case "disk":
      return "text-amber-500 bg-amber-500/10 border-amber-500/20";
    case "network":
      return "text-emerald-500 bg-emerald-500/10 border-emerald-500/20";
    default:
      return "text-muted-foreground bg-muted border-border";
  }
}
