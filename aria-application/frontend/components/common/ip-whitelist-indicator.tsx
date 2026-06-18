"use client";

import { useState, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { ShieldCheck, Loader2 } from "lucide-react";
import { whitelistAPI } from "@/lib/api";

interface IPWhitelistIndicatorProps {
  ip: string | null | undefined;
  className?: string;
  showIcon?: boolean;
  size?: "sm" | "md";
}

export function IPWhitelistIndicator({
  ip,
  className,
  showIcon = true,
  size = "sm",
}: IPWhitelistIndicatorProps) {
  const [whitelisted, setWhitelisted] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [checked, setChecked] = useState<boolean>(false);

  useEffect(() => {
    if (!ip) {
      setWhitelisted(false);
      setChecked(true);
      return;
    }
    let cancelled = false;
    setLoading(true);
    whitelistAPI
      .check(ip)
      .then((result) => {
        if (!cancelled) {
          setWhitelisted(result.whitelisted);
          setChecked(true);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setWhitelisted(false);
          setChecked(true);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [ip]);

  if (!ip || (!whitelisted && checked && !loading)) return null;

  if (loading) {
    return (
      <Loader2
        className={cn(
          "animate-spin text-muted-foreground",
          size === "sm" ? "h-3 w-3" : "h-4 w-4",
          className
        )}
      />
    );
  }

  if (!whitelisted) return null;

  return (
    <Badge
      variant="outline"
      className={cn(
        "bg-emerald-500/10 text-emerald-600 border-emerald-500/30 dark:text-emerald-400 font-normal",
        size === "sm" ? "text-xs px-1.5 py-0 h-5" : "text-xs",
        className
      )}
    >
      {showIcon && <ShieldCheck className={cn("mr-1", size === "sm" ? "h-3 w-3" : "h-3.5 w-3.5")} />}
      Whitelisted
    </Badge>
  );
}
