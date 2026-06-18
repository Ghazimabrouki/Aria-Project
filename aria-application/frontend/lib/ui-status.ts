/**
 * Centralized severity / risk / status -> design-token class mappings.
 *
 * Single source of truth so pages stop hardcoding raw Tailwind palette colors
 * (`bg-red-100`, `bg-amber-500/10`, ...). Every value maps to the oklch design
 * tokens defined in `app/globals.css`, so light/dark mode is handled
 * automatically and the SOC severity language stays consistent everywhere.
 *
 * For badges, prefer the <SeverityBadge> / <StatusBadge> components. Use these
 * helpers for non-badge contexts: table-row tints, inline chips, gauges, bars.
 */

export type Tone = "critical" | "high" | "warning" | "success" | "info" | "neutral";

interface ToneClasses {
  /** Soft tinted surface + text + border — for chips / pills. */
  soft: string;
  /** Text color only. */
  text: string;
  /** Solid background fill — for dots, gauge fills, progress bars. */
  solid: string;
  /** Border color only. */
  border: string;
  /** Very subtle surface tint — for table rows / panel backgrounds. */
  surface: string;
}

const TONES: Record<Tone, ToneClasses> = {
  critical: {
    soft: "bg-destructive/10 text-destructive border-destructive/30",
    text: "text-destructive",
    solid: "bg-destructive",
    border: "border-destructive/30",
    surface: "bg-destructive/5",
  },
  high: {
    soft: "bg-chart-4/10 text-chart-4 border-chart-4/30",
    text: "text-chart-4",
    solid: "bg-chart-4",
    border: "border-chart-4/30",
    surface: "bg-chart-4/5",
  },
  warning: {
    soft: "bg-warning/10 text-warning border-warning/30",
    text: "text-warning",
    solid: "bg-warning",
    border: "border-warning/30",
    surface: "bg-warning/5",
  },
  success: {
    soft: "bg-success/10 text-success border-success/30",
    text: "text-success",
    solid: "bg-success",
    border: "border-success/30",
    surface: "bg-success/5",
  },
  info: {
    soft: "bg-primary/10 text-primary border-primary/30",
    text: "text-primary",
    solid: "bg-primary",
    border: "border-primary/30",
    surface: "bg-primary/5",
  },
  neutral: {
    soft: "bg-muted text-muted-foreground border-border",
    text: "text-muted-foreground",
    solid: "bg-muted-foreground",
    border: "border-border",
    surface: "bg-muted/40",
  },
};

export type ToneVariant = keyof ToneClasses;

/** Raw class string for a given tone + variant. */
export function toneClasses(tone: Tone, variant: ToneVariant = "soft"): string {
  return TONES[tone][variant];
}

// --- Severity / risk -------------------------------------------------------

const SEVERITY_TONE: Record<string, Tone> = {
  critical: "critical",
  high: "high",
  medium: "warning",
  moderate: "warning",
  low: "success",
  informational: "info",
  info: "info",
  none: "neutral",
  unknown: "neutral",
};

/**
 * Normalize a severity / risk value to a Tone. Accepts string labels
 * ("critical", "high", ...) or numeric Wazuh alert levels (0-15).
 */
export function severityTone(severity: string | number | null | undefined): Tone {
  if (typeof severity === "number") {
    if (severity >= 10) return "critical";
    if (severity >= 7) return "high";
    if (severity >= 4) return "warning";
    return "success";
  }
  if (typeof severity === "string") {
    return SEVERITY_TONE[severity.toLowerCase().trim()] ?? "neutral";
  }
  return "neutral";
}

/** Token-based classes for a severity / risk value. */
export function severityClasses(
  severity: string | number | null | undefined,
  variant: ToneVariant = "soft",
): string {
  return toneClasses(severityTone(severity), variant);
}

/** Risk uses the same scale as severity — exported as an alias for clarity. */
export const riskTone = severityTone;
export const riskClasses = severityClasses;

// --- Status ----------------------------------------------------------------

const STATUS_TONE: Record<string, Tone> = {
  // Resolved / healthy / success
  processed: "success",
  resolved: "success",
  completed: "success",
  acknowledged: "success",
  healthy: "success",
  approved: "success",
  executed: "success",
  likely_fixed: "success",
  verified: "success",
  // Needs attention
  active: "warning",
  open: "warning",
  awaiting_approval: "warning",
  degraded: "warning",
  inconclusive: "warning",
  completed_with_warnings: "warning",
  containment: "warning",
  manual_review_required: "warning",
  playbook_failed_but_quiet: "warning",
  escalated: "warning",
  // Failure / danger
  failed: "critical",
  down: "critical",
  blocked: "critical",
  declined: "critical",
  not_fixed: "critical",
  rollback: "critical",
  playbook_failed_problem_worse: "critical",
  // In progress / informational
  new: "info",
  investigating: "info",
  in_progress: "info",
  running: "info",
  executing: "info",
  diagnosing: "info",
  checking: "info",
  current: "info",
  pending_confirmation: "info",
  hardening: "info",
  findings_ready: "info",
  evidence: "info",
  dry_run: "info",
  forensics: "info",
  // Inactive / neutral
  closed: "neutral",
  pending: "neutral",
  archived: "neutral",
  stopped: "neutral",
  disabled: "neutral",
  skipped: "neutral",
  not_applicable: "neutral",
  // Extended ARIA workflow + manual remediation statuses
  observe: "info",
  reopened: "warning",
  remediation_failed: "critical",
  archived_fixed: "success",
  archived_not_fixed: "warning",
  closed_with_risk: "warning",
  manual_remediation_draft: "info",
  manual_remediation_validating: "warning",
  manual_remediation_awaiting_approval: "info",
  manual_remediation_approved: "info",
  manual_remediation_executing: "warning",
  manual_remediation_completed: "success",
  manual_remediation_failed: "critical",
};

/** Normalize a workflow / service status value to a Tone. */
export function statusTone(status: string | null | undefined): Tone {
  if (!status) return "neutral";
  return STATUS_TONE[status.toLowerCase().trim()] ?? "neutral";
}

/** Token-based classes for a status value. */
export function statusClasses(
  status: string | null | undefined,
  variant: ToneVariant = "soft",
): string {
  return toneClasses(statusTone(status), variant);
}

// --- Utilization -----------------------------------------------------------

/** Tone for a 0-100 utilization / usage percentage (CPU, memory, disk...). */
export function usageTone(percent: number): Tone {
  if (percent >= 90) return "critical";
  if (percent >= 70) return "warning";
  return "success";
}

/** Token-based classes for a 0-100 utilization percentage. */
export function usageClasses(percent: number, variant: ToneVariant = "soft"): string {
  return toneClasses(usageTone(percent), variant);
}
