"use client";

import { cn } from "@/lib/utils";

interface LiveIndicatorProps {
  status?: "connected" | "disconnected" | "connecting";
  showLabel?: boolean;
  className?: string;
}

export function LiveIndicator({
  status = "connected",
  showLabel = true,
  className,
}: LiveIndicatorProps) {
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <div className="relative flex h-2.5 w-2.5 items-center justify-center">
        <span
          className={cn(
            "absolute inline-flex h-full w-full rounded-full opacity-75",
            status === "connected" && "animate-ping bg-success",
            status === "disconnected" && "bg-destructive",
            status === "connecting" && "animate-pulse bg-warning"
          )}
        />
        <span
          className={cn(
            "relative inline-flex h-2 w-2 rounded-full",
            status === "connected" && "bg-success",
            status === "disconnected" && "bg-destructive",
            status === "connecting" && "bg-warning"
          )}
        />
      </div>
      {showLabel && (
        <span className="text-xs font-medium text-muted-foreground capitalize">
          {status === "connected" ? "Live" : status}
        </span>
      )}
    </div>
  );
}

interface StatusDotProps {
  status: "critical" | "high" | "medium" | "low" | "info" | "success" | "running" | "pending";
  pulse?: boolean;
  size?: "sm" | "md" | "lg";
  className?: string;
}

export function StatusDot({
  status,
  pulse = false,
  size = "md",
  className,
}: StatusDotProps) {
  const sizeClasses = {
    sm: "h-1.5 w-1.5",
    md: "h-2 w-2",
    lg: "h-2.5 w-2.5",
  };

  const colorClasses = {
    critical: "bg-destructive",
    high: "bg-chart-4",
    medium: "bg-warning",
    low: "bg-chart-2",
    info: "bg-primary",
    success: "bg-success",
    running: "bg-primary",
    pending: "bg-muted-foreground",
  };

  const shouldPulse = pulse || status === "critical" || status === "running";

  return (
    <div className={cn("relative flex items-center justify-center", className)}>
      {shouldPulse && (
        <span
          className={cn(
            "absolute inline-flex rounded-full opacity-50 animate-ping",
            sizeClasses[size],
            colorClasses[status]
          )}
        />
      )}
      <span
        className={cn(
          "relative inline-flex rounded-full",
          sizeClasses[size],
          colorClasses[status]
        )}
      />
    </div>
  );
}
