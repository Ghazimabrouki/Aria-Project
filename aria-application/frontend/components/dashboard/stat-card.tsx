"use client";

import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { AnimatedCounter } from "@/components/animated-counter";
import { type LucideIcon, TrendingUp, TrendingDown } from "lucide-react";

interface StatCardProps {
  title: string;
  value: number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  delta?: string;
  variant?: "default" | "critical" | "warning" | "success";
  className?: string;
  onClick?: () => void;
}

export function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  delta,
  variant = "default",
  className,
  onClick,
}: StatCardProps) {
  return (
    <Card
      className={cn(
        "group relative overflow-hidden transition-all duration-300 hover-lift cursor-pointer card-glow",
        variant === "critical" && "border-destructive/30 hover:border-destructive/50",
        variant === "warning" && "border-warning/30 hover:border-warning/50",
        variant === "success" && "border-success/30 hover:border-success/50",
        variant === "default" && "hover:border-primary/30",
        className
      )}
      onClick={onClick}
    >
      {/* Background gradient effect */}
      <div
        className={cn(
          "absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100",
          variant === "default" && "bg-gradient-to-br from-primary/5 to-transparent",
          variant === "critical" && "bg-gradient-to-br from-destructive/10 to-transparent",
          variant === "warning" && "bg-gradient-to-br from-warning/10 to-transparent",
          variant === "success" && "bg-gradient-to-br from-success/10 to-transparent"
        )}
      />
      
      <CardContent className="relative p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">{title}</p>
            <div className="flex items-baseline gap-2 mt-1.5">
              <AnimatedCounter
                value={value}
                className="text-2xl font-bold tracking-tight"
                duration={800}
              />
              {trend && (
                <div
                  className={cn(
                    "flex items-center gap-0.5 rounded-full px-1.5 py-0.5 text-xs font-semibold shrink-0",
                    trend.isPositive
                      ? "bg-success/10 text-success"
                      : "bg-destructive/10 text-destructive"
                  )}
                >
                  {trend.isPositive ? (
                    <TrendingUp className="h-3 w-3" />
                  ) : (
                    <TrendingDown className="h-3 w-3" />
                  )}
                  {trend.isPositive ? "+" : ""}
                  {trend.value}%
                </div>
              )}
            </div>
            {subtitle && (
              <p className="text-xs text-muted-foreground mt-1 truncate">{subtitle}</p>
            )}
            {delta && (
              <p className="text-xs text-muted-foreground/80 mt-1 truncate">{delta}</p>
            )}
          </div>
          <div
            className={cn(
              "flex h-10 w-10 shrink-0 items-center justify-center rounded-xl transition-transform duration-300 group-hover:scale-110",
              variant === "default" && "bg-primary/10 text-primary",
              variant === "critical" && "bg-destructive/10 text-destructive",
              variant === "warning" && "bg-warning/10 text-warning",
              variant === "success" && "bg-success/10 text-success"
            )}
          >
            <Icon className="h-5 w-5" />
          </div>
        </div>
      </CardContent>
      
      {/* Bottom accent line */}
      <div
        className={cn(
          "absolute bottom-0 left-0 h-0.5 w-full transition-all duration-300",
          variant === "default" && "bg-gradient-to-r from-transparent via-primary to-transparent opacity-0 group-hover:opacity-100",
          variant === "critical" && "bg-gradient-to-r from-transparent via-destructive to-transparent",
          variant === "warning" && "bg-gradient-to-r from-transparent via-warning to-transparent",
          variant === "success" && "bg-gradient-to-r from-transparent via-success to-transparent"
        )}
      />
    </Card>
  );
}

// Skeleton loader for stat card
export function StatCardSkeleton() {
  return (
    <Card className="overflow-hidden">
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-2 flex-1">
            <div className="skeleton h-3 w-20" />
            <div className="skeleton h-7 w-14" />
            <div className="skeleton h-3 w-28" />
          </div>
          <div className="skeleton h-10 w-10 rounded-xl shrink-0" />
        </div>
      </CardContent>
    </Card>
  );
}
