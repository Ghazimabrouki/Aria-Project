"use client";

import { cn } from "@/lib/utils";

interface StatusBadgeProps {
  status: string;
  className?: string;
}

const statusConfig: Record<string, { label: string; className: string; dot?: string }> = {
  // Alert statuses
  new: {
    label: "New",
    className: "bg-primary/10 text-primary border-primary/30",
    dot: "bg-primary animate-pulse",
  },
  active: {
    label: "Active",
    className: "bg-warning/10 text-warning border-warning/30",
    dot: "bg-warning animate-pulse",
  },
  processed: {
    label: "Processed",
    className: "bg-success/10 text-success border-success/30",
    dot: "bg-success",
  },
  // Incident statuses
  open: {
    label: "Open",
    className: "bg-warning/10 text-warning border-warning/30",
    dot: "bg-warning",
  },
  investigating: {
    label: "Investigating",
    className: "bg-primary/10 text-primary border-primary/30",
    dot: "bg-primary animate-pulse",
  },
  in_progress: {
    label: "In Progress",
    className: "bg-primary/10 text-primary border-primary/30",
    dot: "bg-primary animate-pulse",
  },
  resolved: {
    label: "Resolved",
    className: "bg-success/10 text-success border-success/30",
    dot: "bg-success",
  },
  closed: {
    label: "Closed",
    className: "bg-muted text-muted-foreground border-border",
    dot: "bg-muted-foreground",
  },
  // Investigation statuses
  pending: {
    label: "Pending",
    className: "bg-muted text-muted-foreground border-border",
    dot: "bg-muted-foreground",
  },
  current: {
    label: "Current",
    className: "bg-primary/10 text-primary border-primary/30",
    dot: "bg-primary animate-pulse",
  },
  running: {
    label: "Running",
    className: "bg-primary/10 text-primary border-primary/30",
    dot: "bg-primary animate-pulse",
  },
  executing: {
    label: "Executing",
    className: "bg-primary/10 text-primary border-primary/30",
    dot: "bg-primary animate-pulse",
  },
  awaiting_approval: {
    label: "Awaiting Approval",
    className: "bg-warning/10 text-warning border-warning/30",
    dot: "bg-warning animate-pulse",
  },
  completed: {
    label: "Completed",
    className: "bg-success/10 text-success border-success/30",
    dot: "bg-success",
  },
  completed_with_warnings: {
    label: "Completed (Warnings)",
    className: "bg-warning/10 text-warning border-warning/30",
    dot: "bg-warning",
  },
  archived: {
    label: "Archived",
    className: "bg-muted text-muted-foreground border-border",
    dot: "bg-muted-foreground",
  },
  failed: {
    label: "Failed",
    className: "bg-destructive/10 text-destructive border-destructive/30",
    dot: "bg-destructive",
  },
  // Diagnostic-first statuses
  diagnosing: {
    label: "Diagnosing",
    className: "bg-primary/10 text-primary border-primary/30",
    dot: "bg-primary animate-pulse",
  },
  findings_ready: {
    label: "Findings Ready",
    className: "bg-emerald-500/10 text-emerald-500 border-emerald-500/30",
    dot: "bg-emerald-500 animate-pulse",
  },
  acknowledged: {
    label: "Acknowledged",
    className: "bg-success/10 text-success border-success/30",
    dot: "bg-success",
  },
  escalated: {
    label: "Escalated",
    className: "bg-orange-500/10 text-orange-500 border-orange-500/30",
    dot: "bg-orange-500",
  },
  // Service statuses
  healthy: {
    label: "Healthy",
    className: "bg-success/10 text-success border-success/30",
    dot: "bg-success",
  },
  degraded: {
    label: "Degraded",
    className: "bg-warning/10 text-warning border-warning/30",
    dot: "bg-warning",
  },
  down: {
    label: "Down",
    className: "bg-destructive/10 text-destructive border-destructive/30",
    dot: "bg-destructive",
  },
  stopped: {
    label: "Stopped",
    className: "bg-muted text-muted-foreground border-border",
    dot: "bg-muted-foreground",
  },
  disabled: {
    label: "Disabled",
    className: "bg-muted text-muted-foreground border-border",
    dot: "bg-muted-foreground",
  },
  // Playbook statuses
  approved: {
    label: "Approved",
    className: "bg-success/10 text-success border-success/30",
    dot: "bg-success",
  },
  blocked: {
    label: "Blocked",
    className: "bg-destructive/10 text-destructive border-destructive/30",
    dot: "bg-destructive",
  },
  not_applicable: {
    label: "Not Applicable",
    className: "bg-muted text-muted-foreground border-border",
    dot: "bg-muted-foreground",
  },
  manual_review_required: {
    label: "Manual Review",
    className: "bg-amber-500/10 text-amber-500 border-amber-500/30",
    dot: "bg-amber-500",
  },
  declined: {
    label: "Declined",
    className: "bg-destructive/10 text-destructive border-destructive/30",
    dot: "bg-destructive",
  },
  executed: {
    label: "Executed",
    className: "bg-success/10 text-success border-success/30",
    dot: "bg-success",
  },
  skipped: {
    label: "Skipped",
    className: "bg-muted text-muted-foreground border-border",
    dot: "bg-muted-foreground",
  },
  checking: {
    label: "Checking",
    className: "bg-primary/10 text-primary border-primary/30",
    dot: "bg-primary animate-pulse",
  },
  likely_fixed: {
    label: "Likely Fixed",
    className: "bg-success/10 text-success border-success/30",
    dot: "bg-success",
  },
  verified: {
    label: "Verified",
    className: "bg-success/10 text-success border-success/30",
    dot: "bg-success",
  },
  inconclusive: {
    label: "Inconclusive",
    className: "bg-warning/10 text-warning border-warning/30",
    dot: "bg-warning",
  },
  not_fixed: {
    label: "Not Fixed",
    className: "bg-destructive/10 text-destructive border-destructive/30",
    dot: "bg-destructive",
  },
  playbook_failed_but_quiet: {
    label: "Failed But Quiet",
    className: "bg-warning/10 text-warning border-warning/30",
    dot: "bg-warning",
  },
  playbook_failed_problem_worse: {
    label: "Problem Worse",
    className: "bg-destructive/10 text-destructive border-destructive/30",
    dot: "bg-destructive",
  },
  // Staged remediation phases
  evidence: {
    label: "Evidence",
    className: "bg-blue-500/10 text-blue-500 border-blue-500/30",
    dot: "bg-blue-500 animate-pulse",
  },
  dry_run: {
    label: "Dry Run",
    className: "bg-cyan-500/10 text-cyan-600 border-cyan-500/30",
    dot: "bg-cyan-500 animate-pulse",
  },
  containment: {
    label: "Containment",
    className: "bg-warning/10 text-warning border-warning/30",
    dot: "bg-warning animate-pulse",
  },
  hardening: {
    label: "Hardening",
    className: "bg-primary/10 text-primary border-primary/30",
    dot: "bg-primary animate-pulse",
  },
  forensics: {
    label: "Forensics",
    className: "bg-indigo-500/10 text-indigo-500 border-indigo-500/30",
    dot: "bg-indigo-500 animate-pulse",
  },
  verification: {
    label: "Verification",
    className: "bg-success/10 text-success border-success/30",
    dot: "bg-success animate-pulse",
  },
  rollback: {
    label: "Rollback",
    className: "bg-destructive/10 text-destructive border-destructive/30",
    dot: "bg-destructive animate-pulse",
  },
};

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const statusKey = typeof status === "string" ? status.toLowerCase() : "";
  const config = statusConfig[statusKey] || {
    label: status || "Unknown",
    className: "bg-muted text-muted-foreground border-border",
    dot: "bg-muted-foreground",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium",
        config.className,
        className
      )}
    >
      {config.dot && (
        <span className={cn("h-1.5 w-1.5 rounded-full", config.dot)} />
      )}
      {config.label}
    </span>
  );
}
