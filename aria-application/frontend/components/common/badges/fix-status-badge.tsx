"use client";

import { cn } from "@/lib/utils";
import { CheckCircle2, XCircle, AlertTriangle, HelpCircle, Ban, ShieldAlert } from "lucide-react";

const statusConfig: Record<string, { label: string; icon: React.ElementType; className: string }> = {
  likely_fixed: { label: "Likely Fixed", icon: CheckCircle2, className: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20" },
  verified: { label: "Verified Fixed", icon: CheckCircle2, className: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20" },
  archived_fixed: { label: "Fixed", icon: CheckCircle2, className: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20" },
  not_fixed: { label: "Not Fixed", icon: XCircle, className: "bg-destructive/10 text-destructive border-destructive/20" },
  playbook_failed_problem_worse: { label: "Problem Worse", icon: ShieldAlert, className: "bg-destructive/10 text-destructive border-destructive/20" },
  inconclusive: { label: "Inconclusive", icon: HelpCircle, className: "bg-amber-500/10 text-amber-500 border-amber-500/20" },
  playbook_failed_but_quiet: { label: "Failed (Quiet)", icon: AlertTriangle, className: "bg-amber-500/10 text-amber-500 border-amber-500/20" },
  declined: { label: "Declined", icon: Ban, className: "bg-muted text-muted-foreground border-border" },
  unknown: { label: "Unknown", icon: HelpCircle, className: "bg-muted text-muted-foreground border-border" },
};

export function FixStatusBadge({ status, className }: { status: string; className?: string }) {
  const config = statusConfig[status] || statusConfig.unknown;
  const Icon = config.icon;
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium", config.className, className)}>
      <Icon className="h-3.5 w-3.5" />
      {config.label}
    </span>
  );
}
