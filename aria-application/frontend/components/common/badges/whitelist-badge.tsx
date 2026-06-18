"use client";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { ShieldCheck } from "lucide-react";

interface WhitelistBadgeProps {
  whitelisted: boolean;
  className?: string;
  showIcon?: boolean;
}

export function WhitelistBadge({ whitelisted, className, showIcon = true }: WhitelistBadgeProps) {
  if (!whitelisted) return null;

  return (
    <Badge
      variant="outline"
      className={cn(
        "bg-emerald-500/10 text-emerald-600 border-emerald-500/30 dark:text-emerald-400",
        className
      )}
    >
      {showIcon && <ShieldCheck className="mr-1 h-3 w-3" />}
      Whitelisted
    </Badge>
  );
}
