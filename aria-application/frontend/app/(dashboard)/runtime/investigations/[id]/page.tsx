"use client";

import { use, useState } from "react";
import useSWR from "swr";
import { useRouter } from "next/navigation";
import { formatAbsoluteDateTime } from "@/lib/time";
import {
  ArrowLeft,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Play,
  Clock,
  Activity,
  Terminal,
  Server,
  HardDrive,
  User,
  FileText,
  History,
  ThumbsUp,
  ThumbsDown,
  Eye,
  FileCode,
  Gauge,
  Microscope,
  RotateCcw,
  ChevronDown,
  Info,
  ListChecks,
  KeyRound,
  AlertOctagon,
  Lightbulb,
  Code2,
  Wrench,
} from "lucide-react";
import { runtimeAPI, type RuntimeInvestigation } from "@/lib/api";
import { useWSSubscription } from "@/lib/websocket";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Collapsible, CollapsibleTrigger, CollapsibleContent } from "@/components/ui/collapsible";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { cn } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { AdminOverridePanel } from "@/components/runtime/admin-override-panel";

const STATUS_COLOR: Record<string, string> = {
  diagnosing: "bg-amber-500/10 text-amber-500 border-amber-500/20",
  findings_ready: "bg-amber-500/10 text-amber-500 border-amber-500/20",
  observe: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  manual_review_required: "bg-amber-500/10 text-amber-500 border-amber-500/20",
  acknowledged: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
  escalated: "bg-rose-500/10 text-rose-500 border-rose-500/20",
  awaiting_approval: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  approved: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  running: "bg-amber-500/10 text-amber-500 border-amber-500/20",
  completed: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
  verified: "bg-emerald-600/10 text-emerald-600 border-emerald-600/20",
  fixed: "bg-emerald-600/10 text-emerald-600 border-emerald-600/20",
  not_fixed: "bg-destructive/10 text-destructive border-destructive/20",
  inconclusive: "bg-amber-500/10 text-amber-500 border-amber-500/20",
  remediation_failed: "bg-destructive/10 text-destructive border-destructive/20",
  verification_failed: "bg-destructive/10 text-destructive border-destructive/20",
  failed: "bg-destructive/10 text-destructive border-destructive/20",
  declined: "bg-muted/10 text-muted-foreground border-muted/20",
  archived_fixed: "bg-emerald-600/10 text-emerald-600 border-emerald-600/20",
  archived_not_fixed: "bg-amber-500/10 text-amber-500 border-amber-500/20",
  closed_with_risk: "bg-amber-500/10 text-amber-500 border-amber-500/20",
  manual_remediation_draft: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  manual_remediation_validating: "bg-amber-500/10 text-amber-500 border-amber-500/20",
  manual_remediation_awaiting_approval: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  manual_remediation_approved: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  manual_remediation_executing: "bg-amber-500/10 text-amber-500 border-amber-500/20",
  manual_remediation_completed: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
  manual_remediation_failed: "bg-destructive/10 text-destructive border-destructive/20",
  reopened: "bg-rose-500/10 text-rose-500 border-rose-500/20",
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: "bg-red-500/10 text-red-500 border-red-500/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  medium: "bg-amber-500/10 text-amber-500 border-amber-500/20",
  low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  info: "bg-slate-500/10 text-slate-500 border-slate-500/20",
};

const THREAT_COLOR: Record<string, string> = {
  malicious: "bg-red-500/10 text-red-500 border-red-500/20",
  suspicious: "bg-amber-500/10 text-amber-500 border-amber-500/20",
  expected: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
  expected_administrative_activity: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
  observe: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  unknown: "bg-slate-500/10 text-slate-500 border-slate-500/20",
};

export default function RuntimeInvestigationDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const router = useRouter();
  const [activeTab, setActiveTab] = useState("overview");
  const [actionLoading, setActionLoading] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const { toast } = useToast();

  const { data: _inv, error, isLoading, mutate } = useSWR<RuntimeInvestigation>(
    id ? `runtime-investigation-${id}` : null,
    () => runtimeAPI.get(id),
    { refreshInterval: 10000 }
  );
  const inv = _inv as RuntimeInvestigation | undefined;

  useWSSubscription("investigation_updated", (msg: any) => {
    if (msg.data?.investigation_id === id) {
      mutate();
    }
  });

  const ctx = inv?.resource_context;
  const classification = inv?.classification_context;
  const findings = inv?.findings_json;
  const plan = inv?.remediation_plan;
  const outcome = inv?.outcome_summary;
  const availableActions = inv?.available_actions;
  const playbookSummary = inv?.playbook_summary;

  const ACTION_LABELS: Record<string, string> = {
    acknowledge: "Acknowledged",
    escalate: "Escalated",
    approve: "Approved",
    decline: "Declined",
    diagnose: "Re-diagnosis started",
    archive: "Archived",
  };

  function getActionMessage(value: unknown): string {
    if (value == null) return "";
    if (typeof value === "string") return value;
    if (typeof value === "number" || typeof value === "boolean") return String(value);
    if (value instanceof Error) return value.message || "Error";
    if (typeof value === "object") {
      const obj = value as Record<string, unknown>;
      if (typeof obj.message === "string" && obj.message) return obj.message;
      if (typeof obj.detail === "string" && obj.detail) return obj.detail;
      if (typeof obj.error === "string" && obj.error) return obj.error;
      if (obj.detail && typeof obj.detail === "object") {
        const detail = obj.detail as Record<string, unknown>;
        if (typeof detail.message === "string" && detail.message) return detail.message;
      }
      try {
        const s = JSON.stringify(value);
        if (s !== "{}" && s !== "[]") return s;
      } catch { /* ignore */ }
    }
    return "";
  }

  function buildSuccessMessage(action: string, res: any): string {
    const backendMsg = getActionMessage(res?.message) || getActionMessage(res?.detail);
    if (backendMsg) {
      if (action === "escalate" && res?.remediation_generated === false) {
        return `No remediation was generated. ${backendMsg}`;
      }
      return backendMsg;
    }
    const defaults: Record<string, string> = {
      acknowledge: "Investigation acknowledged successfully.",
      escalate: "Investigation escalated.",
      approve: "Playbook approved and execution started.",
      decline: "Remediation declined.",
      diagnose: "Diagnostic pipeline restarted.",
      archive: "Investigation archived.",
    };
    return defaults[action] || "Action completed successfully.";
  }

  const handleAction = async (action: string) => {
    setActionLoading(true);
    setActionError(null);
    try {
      let res: any;
      if (action === "acknowledge") res = await runtimeAPI.acknowledge(id);
      if (action === "escalate") res = await runtimeAPI.escalate(id);
      if (action === "approve") res = await runtimeAPI.approve(id);
      if (action === "decline") res = await runtimeAPI.decline(id);
      if (action === "diagnose") res = await runtimeAPI.diagnose(id);
      if (action === "archive") res = await runtimeAPI.archive(id);

      await mutate();

      const label = ACTION_LABELS[action] || action;
      const message = buildSuccessMessage(action, res);
      toast({
        title: label,
        description: message,
      });
    } catch (e: any) {
      const msg = getActionMessage(e) || "Action failed. Please try again.";
      setActionError(msg);
      toast({
        title: "Action failed",
        description: msg,
        variant: "destructive",
      });
      console.error(e);
    } finally {
      setActionLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-4 animate-fade-in">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-lg bg-muted" />
          <div className="space-y-2">
            <div className="h-5 w-48 bg-muted rounded" />
            <div className="h-3 w-32 bg-muted rounded" />
          </div>
        </div>
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="rounded-lg border p-4 space-y-3">
            <div className="h-4 w-32 bg-muted rounded" />
            <div className="h-3 w-full bg-muted rounded" />
            <div className="h-3 w-2/3 bg-muted rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (error || !inv) {
    console.error("[RuntimeDetail] Render error state:", { id, error: error?.message, inv });
    return (
      <div className="p-6">
        <div className="text-center text-destructive py-12">
          <AlertTriangle className="h-8 w-8 mx-auto mb-2" />
          Failed to load investigation
          {error && <div className="text-xs mt-2 text-muted-foreground">{error.message}</div>}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={() => router.push("/runtime/investigations")}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-xl font-bold">{inv.incident_title}</h1>
            <div className="flex items-center gap-2 mt-1">
              <Badge variant="outline" className={cn(STATUS_COLOR[inv.status] || "")}>
                {inv.status.replace(/_/g, " ")}
              </Badge>
              <Badge variant="outline" className={cn(SEVERITY_COLOR[inv.incident_severity] || "")}>
                {inv.incident_severity}
              </Badge>
              {ctx?.runtime_category && (
                <Badge variant="outline" className="text-xs">
                  {ctx.runtime_category.replace(/_/g, " ")}
                </Badge>
              )}
              <span className="text-xs text-muted-foreground">
                {formatAbsoluteDateTime(inv.created_at)}
              </span>
            </div>
          </div>
        </div>

        <div className="flex flex-col items-end gap-2">
          {actionError && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive max-w-md text-right">
              {actionError}
            </div>
          )}
          <div className="flex items-center gap-2">
            {availableActions?.acknowledge && (
              <Button variant="outline" size="sm" onClick={() => handleAction("acknowledge")} disabled={actionLoading} className="gap-1.5">
                <ThumbsUp className="h-3.5 w-3.5" />
                Acknowledge
              </Button>
            )}
            {availableActions?.escalate && (
              <Button variant="default" size="sm" onClick={() => handleAction("escalate")} disabled={actionLoading} className="gap-1.5">
                <AlertTriangle className="h-3.5 w-3.5" />
                Escalate
              </Button>
            )}
            {availableActions?.decline && (
              <Button variant="outline" size="sm" onClick={() => handleAction("decline")} disabled={actionLoading} className="gap-1.5">
                <ThumbsDown className="h-3.5 w-3.5" />
                Decline
              </Button>
            )}
            {availableActions?.approve_run && (
              <Button variant="default" size="sm" onClick={() => handleAction("approve")} disabled={actionLoading} className="gap-1.5">
                <ShieldCheck className="h-3.5 w-3.5" />
                Approve & Run
              </Button>
            )}
            {availableActions?.archive && (
              <Button variant="outline" size="sm" onClick={() => handleAction("archive")} disabled={actionLoading}>
                Archive
              </Button>
            )}
            {availableActions?.rediagnose && (
              <Button variant="ghost" size="sm" onClick={() => handleAction("diagnose")} disabled={actionLoading} className="gap-1.5">
                <Microscope className="h-3.5 w-3.5" />
                Re-diagnose
              </Button>
            )}
            {/* Actions are always driven by available_actions from the backend */}
          </div>
        </div>
      </div>

      {/* Admin Override Panel */}
      {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
      {inv ? (<AdminOverridePanel investigation={inv} onMutate={mutate} /> as any) : null}

      {/* Data quality warnings */}
      {classification?._data_quality && Object.keys(classification._data_quality).length > 0 && (
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-amber-500 shrink-0 mt-0.5" />
              <div className="space-y-2">
                <div className="text-sm font-medium text-amber-700">Data Quality Warning</div>
                {Object.entries(classification._data_quality).map(([field, info]: [string, any]) => (
                  <div key={field} className="text-sm text-amber-700/90">
                    <span className="font-medium capitalize">{field.replace(/_/g, " ")}:</span>{" "}
                    {info?.reason || String(info)}
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Remediation readiness banner */}
      {inv.target_asset ? (
        inv.target_asset.remediation_enabled && inv.target_asset.ansible_host ? (
          <Card className="border-emerald-500/30 bg-emerald-500/5">
            <CardContent className="p-4">
              <div className="flex items-start gap-3">
                <ShieldCheck className="h-5 w-5 text-emerald-500 shrink-0 mt-0.5" />
                <div className="text-sm">
                  <p className="font-medium text-emerald-700 dark:text-emerald-400">
                    Remediation ready — {inv.target_asset.name}
                  </p>
                  <p className="text-emerald-700/80 dark:text-emerald-400/80 mt-0.5">
                    Target host <span className="font-mono font-medium">{inv.target_asset.ansible_host}</span>
                    {inv.target_asset.ansible_user && (
                      <> via user <span className="font-mono font-medium">{inv.target_asset.ansible_user}</span></>
                    )}
                    {inv.target_asset.ansible_port && inv.target_asset.ansible_port !== 22 && (
                      <> on port <span className="font-mono font-medium">{inv.target_asset.ansible_port}</span></>
                    )}
                    . Playbook execution will target this asset when approved.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        ) : (
          <Card className="border-amber-500/30 bg-amber-500/5">
            <CardContent className="p-4">
              <div className="flex items-start gap-3">
                <Wrench className="h-5 w-5 text-amber-500 shrink-0 mt-0.5" />
                <div className="text-sm">
                  <p className="font-medium text-amber-700 dark:text-amber-400">
                    Remediation not configured — {inv.target_asset.name}
                  </p>
                  <p className="text-amber-700/80 dark:text-amber-400/80 mt-0.5">
                    {inv.target_asset.enabled
                      ? "This asset is enabled but remediation is disabled or the Ansible host is not set."
                      : "This asset is currently disabled."}{" "}
                    Configure remediation in{" "}
                    <a
                      href={`/settings/ansible?asset_id=${inv.target_asset.asset_id}`}
                      className="underline font-medium"
                    >
                      Settings → Ansible
                    </a>
                    .
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        )
      ) : inv.asset_id ? (
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <Wrench className="h-5 w-5 text-amber-500 shrink-0 mt-0.5" />
              <div className="text-sm">
                <p className="font-medium text-amber-700 dark:text-amber-400">
                  Asset not found
                </p>
                <p className="text-amber-700/80 dark:text-amber-400/80 mt-0.5">
                  This investigation is linked to asset <span className="font-mono">{inv.asset_id}</span>, but the asset
                  no longer exists in the system. Remediation cannot be executed until the asset is re-created.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card className="border-blue-200/60 bg-blue-50/40 dark:border-blue-900/40 dark:bg-blue-950/20">
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <Info className="h-5 w-5 text-blue-500 shrink-0 mt-0.5" />
              <div className="text-sm">
                <p className="font-medium text-blue-700 dark:text-blue-400">
                  No target asset assigned
                </p>
                <p className="text-blue-700/80 dark:text-blue-400/80 mt-0.5">
                  This investigation is not linked to a monitored asset. Remediation will use global Ansible settings
                  or the host derived from alert data ({inv.target_host || "unknown"}).{" "}
                  <a href="/settings/assets" className="underline font-medium">
                    Link an asset
                  </a>{" "}
                  for per-server targeting and tracking.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Card className="border-primary/20">
        <CardContent className="p-4">
          <div className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline" className={cn(STATUS_COLOR[inv.status] || "")}>
                  Final: {inv.status.replace(/_/g, " ")}
                </Badge>
                {plan?.decision && (
                  <Badge variant="outline">{plan.decision.replace(/_/g, " ")}</Badge>
                )}
                {plan?.target_context && (
                  <Badge variant="outline">{plan.target_context}</Badge>
                )}
                {plan?.confidence != null && (
                  <ConfidenceBadge confidence={plan.confidence} />
                )}
                {outcome?.fixed ? (
                  <Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
                    fixed
                  </Badge>
                ) : outcome?.unresolved_risk ? (
                  <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500/20">
                    {plan?.decision === "manual_review_required" ? "manual review" : "unresolved risk"}
                  </Badge>
                ) : plan?.decision === "observe" || plan?.decision === "no_action_expected_activity" ? (
                  <Badge variant="outline" className="bg-blue-500/10 text-blue-500 border-blue-500/20">
                    observe
                  </Badge>
                ) : null}
              </div>
              <p className="text-sm leading-relaxed">
                {outcome?.message || findings?.expert_summary || inv.ai_summary || "Runtime investigation is waiting for diagnostic interpretation."}
              </p>
              <div className="text-sm">
                <span className="text-muted-foreground">Next action: </span>
                <span className="font-medium">{outcome?.next_action || "Review evidence and planner decision."}</span>
              </div>
              {plan?.legacy_inconsistent_state && (
                <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-700 dark:text-amber-300">
                  Historical/pre-fix data: this case had an approval/remediation artifact without corrective actions. Approval is blocked.
                </div>
              )}
            </div>
            <div className="space-y-2 text-sm">
              <DetailRow label="Scope" value={plan?.affected_scope || "—"} />
              <DetailRow label="Why" value={plan?.scope_reason || "—"} />
              <DetailRow label="Diagnostic" value={inv.diagnostic_summary?.message || "—"} />
              <DetailRow label="Remediation" value={inv.remediation_summary?.message || "—"} />
            </div>
          </div>
        </CardContent>
      </Card>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-8 lg:w-auto lg:inline-grid">
          <TabsTrigger value="overview" className="gap-1.5">
            <ShieldCheck className="h-4 w-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="evidence" className="gap-1.5">
            <FileText className="h-4 w-4" />
            Evidence
          </TabsTrigger>
          <TabsTrigger value="diagnostic" className="gap-1.5">
            <Microscope className="h-4 w-4" />
            Diagnostic
          </TabsTrigger>
          <TabsTrigger value="remediation" className="gap-1.5">
            <FileCode className="h-4 w-4" />
            Remediation
          </TabsTrigger>
          <TabsTrigger value="verification" className="gap-1.5">
            <CheckCircle2 className="h-4 w-4" />
            Verification
          </TabsTrigger>
          <TabsTrigger value="context" className="gap-1.5">
            <Terminal className="h-4 w-4" />
            Context
          </TabsTrigger>
          <TabsTrigger value="timeline" className="gap-1.5">
            <History className="h-4 w-4" />
            Timeline
          </TabsTrigger>
          <TabsTrigger value="raw" className="gap-1.5">
            <FileCode className="h-4 w-4" />
            Raw Output
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          {findings ? (
            <>
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Gauge className="h-4 w-4 text-primary" />
                    Expert Summary
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center gap-2">
                    {findings.threat_assessment && (
                      <Badge variant="outline" className={cn(THREAT_COLOR[findings.threat_assessment] || "")}>
                        {findings.threat_assessment.replace(/_/g, " ")}
                      </Badge>
                    )}
                    <ConfidenceBadge confidence={findings.confidence || 0} />
                  </div>
                  <p className="text-sm leading-relaxed">{findings.expert_summary}</p>
                  {findings.detected_cause && (
                    <div className="bg-accent/50 rounded-lg p-3">
                      <div className="text-xs text-muted-foreground mb-1">Detected Cause</div>
                      <div className="text-sm font-medium">{findings.detected_cause}</div>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Activity className="h-4 w-4 text-primary" />
                    Technical Explanation
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm leading-relaxed text-muted-foreground">
                    {findings.technical_explanation}
                  </p>
                </CardContent>
              </Card>

              {findings.recommendations && findings.recommendations.length > 0 && (
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base flex items-center gap-2">
                      <ShieldCheck className="h-4 w-4 text-primary" />
                      Recommendations
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {findings.recommendations.map((rec: any, i: number) => (
                      <div key={i} className="bg-accent/30 rounded-lg p-3">
                        <div className="flex items-center gap-2 mb-1">
                          <PriorityBadge priority={rec.priority} />
                          <span className="text-xs text-muted-foreground">Risk: {rec.risk}</span>
                        </div>
                        <p className="text-sm">{rec.action}</p>
                        {rec.rationale && (
                          <p className="text-xs text-muted-foreground mt-1">{rec.rationale}</p>
                        )}
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}
            </>
          ) : (
            <div className="text-center text-muted-foreground py-12">
              <Clock className="h-8 w-8 mx-auto mb-2 text-muted-foreground/50" />
              {inv.status === "diagnosing" ? "Diagnostic in progress..." : "No findings available yet."}
            </div>
          )}
        </TabsContent>

        <TabsContent value="context" className="space-y-4">
          {ctx ? (
            <>
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Server className="h-4 w-4 text-primary" />
                    Scope
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <DetailRow label="Target" value={plan?.target_context || "—"} />
                  <DetailRow label="Affected" value={plan?.affected_scope || "—"} />
                  <DetailRow label="Reason" value={plan?.scope_reason || "—"} />
                  <DetailRow label="Host" value={ctx.hostname || inv.target_host || "—"} />
                  <DetailRow label="Container" value={ctx.container_name || ctx.container_id || "host"} />
                  <DetailRow label="Image" value={[ctx.container_image_repository, ctx.container_image_tag].filter(Boolean).join(":") || "—"} />
                  <DetailRow label="Kubernetes" value={[ctx.k8s_ns_name, ctx.k8s_pod_name].filter(Boolean).join("/") || "—"} />
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-primary" />
                    Process
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <DetailRow label="Name" value={ctx.proc_name || "—"} />
                  <DetailRow label="PID" value={ctx.proc_pid?.toString() || "—"} mono />
                  <DetailRow label="Command Line" value={ctx.proc_cmdline || "—"} />
                  <DetailRow label="Binary Path" value={ctx.proc_exepath || "—"} mono />
                  <DetailRow label="Parent" value={`${ctx.proc_pname || "—"} (PPID ${ctx.proc_ppid || "—"})`} />
                  {ctx.proc_ancestors && ctx.proc_ancestors.length > 0 && (
                    <DetailRow label="Ancestors" value={ctx.proc_ancestors.join(" -> ")} />
                  )}
                  {ctx.proc_tty && <DetailRow label="TTY" value={ctx.proc_tty.toString()} mono />}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <User className="h-4 w-4 text-primary" />
                    User
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <DetailRow label="Effective User" value={ctx.user_name || "—"} />
                  <DetailRow label="Effective UID" value={ctx.user_uid?.toString() || "—"} mono />
                  <DetailRow label="Login UID" value={ctx.user_loginuid?.toString() || "—"} mono />
                </CardContent>
              </Card>

              {ctx.fd_name && (
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base flex items-center gap-2">
                      <HardDrive className="h-4 w-4 text-primary" />
                      File
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <DetailRow label="Path" value={ctx.fd_name} mono />
                    <DetailRow label="Type" value={ctx.fd_type || "—"} />
                  </CardContent>
                </Card>
              )}

              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Activity className="h-4 w-4 text-primary" />
                    Event
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <DetailRow label="Rule" value={ctx.rule_name || "—"} />
                  <DetailRow label="Priority" value={ctx.priority || "—"} />
                  <DetailRow label="Category" value={ctx.runtime_category?.replace(/_/g, " ") || "—"} />
                  <DetailRow label="Event Type" value={ctx.evt_type || "—"} />
                  <DetailRow label="Event Category" value={ctx.evt_category || "—"} />
                  <DetailRow label="Host" value={ctx.hostname || "—"} />
                  {ctx.mitre_techniques && ctx.mitre_techniques.length > 0 && (
                    <div className="flex items-start gap-2">
                      <span className="text-xs text-muted-foreground w-24 shrink-0">MITRE</span>
                      <div className="flex flex-wrap gap-1">
                        {ctx.mitre_techniques.map((t: string) => (
                          <Badge key={t} variant="outline" className="text-xs">{t}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </>
          ) : (
            <div className="text-center text-muted-foreground py-12">No runtime context available</div>
          )}
        </TabsContent>

        <TabsContent value="diagnostic" className="space-y-4">
          {/* 1. Diagnostic Result Card */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Microscope className="h-4 w-4 text-primary" />
                Diagnostic Result
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge className={cn(STATUS_COLOR[inv.diagnostic_summary?.status || inv.status || ""] || "bg-slate-500/10 text-slate-500 border-slate-500/20")}>
                  {inv.diagnostic_summary?.status || inv.status || "Unknown"}
                </Badge>
                <Badge variant="outline">{plan?.actual_remediation_available ? "Remediation available" : "Evidence collection only"}</Badge>
                {inv.diagnostic_summary?.target_context && (
                  <Badge variant="secondary" className="capitalize">
                    {inv.diagnostic_summary.target_context}
                  </Badge>
                )}
                {typeof inv.diagnostic_summary?.confidence === "number" && (
                  <ConfidenceBadge confidence={inv.diagnostic_summary.confidence} />
                )}
              </div>

              {inv.diagnostic_summary?.target && (
                <div className="text-sm">
                  <span className="text-muted-foreground">Target:</span>{" "}
                  <span className="font-medium">{inv.diagnostic_summary.target}</span>
                </div>
              )}

              {inv.diagnostic_summary?.main_finding && (
                <div className="rounded-lg bg-accent/40 p-3">
                  <div className="text-xs text-muted-foreground mb-1">Main finding</div>
                  <div className="text-sm font-medium">{inv.diagnostic_summary.main_finding}</div>
                </div>
              )}

              {inv.diagnostic_summary?.conclusion && (
                <div className="text-sm text-muted-foreground">
                  {inv.diagnostic_summary.conclusion}
                </div>
              )}

              {inv.diagnostic_summary?.meaning && (
                <Alert>
                  <Info className="h-4 w-4" />
                  <AlertTitle>What this means</AlertTitle>
                  <AlertDescription>{inv.diagnostic_summary.meaning}</AlertDescription>
                </Alert>
              )}

              {inv.diagnostic_summary?.next_steps && inv.diagnostic_summary.next_steps.length > 0 && (
                <div className="rounded-lg border border-primary/20 bg-primary/5 p-3">
                  <div className="text-xs font-medium text-primary mb-2 flex items-center gap-1.5">
                    <Lightbulb className="h-3.5 w-3.5" />
                    Recommended next step
                  </div>
                  <div className="text-sm">{inv.diagnostic_summary.next_steps[0]}</div>
                </div>
              )}

              {inv.diagnostic_summary?.error && (
                <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
                  {inv.diagnostic_summary.error}
                </div>
              )}
            </CardContent>
          </Card>

          {/* 2. What Was Checked */}
          {inv.diagnostic_summary?.checked_items && inv.diagnostic_summary.checked_items.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <ListChecks className="h-4 w-4 text-primary" />
                  What Was Checked
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {inv.diagnostic_summary.checked_items.map((item, i) => (
                  <div key={i} className="flex items-start gap-3 rounded-lg border p-3">
                    {item.status === "checked" ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-500 mt-0.5 shrink-0" />
                    ) : item.status === "failed" ? (
                      <XCircle className="h-4 w-4 text-destructive mt-0.5 shrink-0" />
                    ) : (
                      <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5 shrink-0" />
                    )}
                    <div className="min-w-0">
                      <div className="text-sm font-medium">{item.name}</div>
                      <div className="text-xs text-muted-foreground mt-0.5">{item.result}</div>
                      {item.important_values && Object.keys(item.important_values).length > 0 && (
                        <div className="flex flex-wrap gap-1.5 mt-1.5">
                          {Object.entries(item.important_values).map(([k, v]) => (
                            <Badge key={k} variant="outline" className="text-xs font-mono">
                              {k}: {String(v)}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* 3. Key Evidence Extracted */}
          {inv.diagnostic_summary?.evidence_extracted && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <KeyRound className="h-4 w-4 text-primary" />
                  Key Evidence Extracted
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {inv.diagnostic_summary.evidence_extracted.file_exists !== null && inv.diagnostic_summary.evidence_extracted.file_exists !== undefined && (
                    <EvidenceItem label="File exists" value={inv.diagnostic_summary.evidence_extracted.file_exists ? "Yes" : "No"} status={inv.diagnostic_summary.evidence_extracted.file_exists ? "ok" : "warning"} />
                  )}
                  {inv.diagnostic_summary.evidence_extracted.file_permissions && (
                    <EvidenceItem label="File permissions" value={inv.diagnostic_summary.evidence_extracted.file_permissions} />
                  )}
                  {inv.diagnostic_summary.evidence_extracted.file_hash && (
                    <EvidenceItem label="File hash (sha256)" value={inv.diagnostic_summary.evidence_extracted.file_hash} mono />
                  )}
                  {inv.diagnostic_summary.evidence_extracted.service_status && (
                    <EvidenceItem label="Service status" value={inv.diagnostic_summary.evidence_extracted.service_status} />
                  )}
                  {typeof inv.diagnostic_summary.evidence_extracted.failed_units_count === "number" && (
                    <EvidenceItem label="Failed units" value={String(inv.diagnostic_summary.evidence_extracted.failed_units_count)} status={inv.diagnostic_summary.evidence_extracted.failed_units_count > 0 ? "warning" : "ok"} />
                  )}
                  {typeof inv.diagnostic_summary.evidence_extracted.recent_errors_count === "number" && (
                    <EvidenceItem label="Recent errors" value={String(inv.diagnostic_summary.evidence_extracted.recent_errors_count)} status={inv.diagnostic_summary.evidence_extracted.recent_errors_count > 0 ? "warning" : "ok"} />
                  )}
                  {inv.diagnostic_summary.evidence_extracted.process_running !== null && inv.diagnostic_summary.evidence_extracted.process_running !== undefined && (
                    <EvidenceItem label="Process running" value={inv.diagnostic_summary.evidence_extracted.process_running ? "Yes" : "No"} />
                  )}
                  {inv.diagnostic_summary.evidence_extracted.container_inspected !== null && inv.diagnostic_summary.evidence_extracted.container_inspected !== undefined && (
                    <EvidenceItem label="Container inspected" value={inv.diagnostic_summary.evidence_extracted.container_inspected ? "Yes" : "No"} />
                  )}
                  {inv.diagnostic_summary.evidence_extracted.command_execution_status && (
                    <EvidenceItem label="Diagnostic execution" value={inv.diagnostic_summary.evidence_extracted.command_execution_status} />
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* 4. Diagnostic Problems / Gaps */}
          {inv.diagnostic_summary?.diagnostic_gaps && inv.diagnostic_summary.diagnostic_gaps.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <AlertOctagon className="h-4 w-4 text-amber-500" />
                  Diagnostic Problems / Gaps
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {inv.diagnostic_summary.diagnostic_gaps.map((gap, i) => (
                  <div key={i} className="flex items-start gap-2 rounded-md bg-amber-500/10 border border-amber-500/20 p-3 text-sm text-amber-700">
                    <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                    <span>{gap}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* 5. Diagnostic Meaning (standalone if not in result card) */}
          {!inv.diagnostic_summary?.meaning && findings?.technical_explanation && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Info className="h-4 w-4 text-primary" />
                  Diagnostic Meaning
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">{findings.technical_explanation}</p>
              </CardContent>
            </Card>
          )}

          {/* 6. Recommended Next Steps */}
          {inv.diagnostic_summary?.next_steps && inv.diagnostic_summary.next_steps.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Lightbulb className="h-4 w-4 text-primary" />
                  Recommended Next Steps
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ol className="space-y-2 list-decimal list-inside">
                  {inv.diagnostic_summary.next_steps.map((step, i) => (
                    <li key={i} className="text-sm text-muted-foreground">{step}</li>
                  ))}
                </ol>
              </CardContent>
            </Card>
          )}

          {/* 7. Advanced Technical Evidence (collapsible) */}
          <div className="space-y-3 pt-2">
            {playbookSummary?.diagnostic_playbook_yaml && (
              <Collapsible>
                <CollapsibleTrigger asChild>
                  <Button variant="outline" className="w-full justify-between">
                    <span className="flex items-center gap-2">
                      <Code2 className="h-4 w-4" />
                      Show diagnostic playbook
                    </span>
                    <ChevronDown className="h-4 w-4 shrink-0 transition-transform data-[state=open]:rotate-180" />
                  </Button>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <Card className="mt-2">
                    <CardContent className="pt-4">
                      <pre className="bg-muted rounded-lg p-4 text-xs overflow-auto max-h-[360px] whitespace-pre-wrap">
                        {playbookSummary.diagnostic_playbook_yaml}
                      </pre>
                    </CardContent>
                  </Card>
                </CollapsibleContent>
              </Collapsible>
            )}

            <Collapsible>
              <CollapsibleTrigger asChild>
                <Button variant="outline" className="w-full justify-between">
                  <span className="flex items-center gap-2">
                    <Terminal className="h-4 w-4" />
                    Show raw diagnostic output
                  </span>
                  <ChevronDown className="h-4 w-4 shrink-0 transition-transform data-[state=open]:rotate-180" />
                </Button>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <Card className="mt-2">
                  <CardContent className="pt-4">
                    {inv.diagnostic_output ? (
                      <pre className="bg-muted rounded-lg p-4 text-xs overflow-auto max-h-[600px] whitespace-pre-wrap">
                        {inv.diagnostic_output}
                      </pre>
                    ) : (
                      <div className="text-center text-muted-foreground py-8">
                        {inv.status === "diagnosing" ? "Diagnostic playbook is currently running..." : "No diagnostic output available."}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </CollapsibleContent>
            </Collapsible>
          </div>
        </TabsContent>

        <TabsContent value="evidence" className="space-y-4">
          {findings?.evidence && findings.evidence.length > 0 ? (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <FileText className="h-4 w-4 text-primary" />
                  Evidence ({findings.evidence.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {findings.evidence.map((ev: any, i: number) => (
                  <div key={i} className="bg-accent/30 rounded-lg p-3">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant="outline" className="text-xs">{ev.source}</Badge>
                      {ev.timestamp && <span className="text-xs text-muted-foreground">{ev.timestamp}</span>}
                    </div>
                    <p className="text-sm font-mono break-all">{ev.finding}</p>
                  </div>
                ))}
              </CardContent>
            </Card>
          ) : (
            <div className="text-center text-muted-foreground py-12">
              <FileText className="h-8 w-8 mx-auto mb-2 text-muted-foreground/50" />
              No evidence collected yet
            </div>
          )}
        </TabsContent>

        <TabsContent value="remediation" className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <FileCode className="h-4 w-4 text-primary" />
                Remediation Plan
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2 text-sm">
                <DetailRow label="Decision" value={plan?.decision?.replace(/_/g, " ") || "—"} />
                <DetailRow label="Reason" value={plan?.decision_reason || "—"} />
                <DetailRow label="Approval" value={plan?.approval_required ? "Required" : "Not available / not required"} />
                <DetailRow label="Destructive" value={plan?.destructive_action ? "Yes" : "No"} />
              </div>
              {!plan?.actual_remediation_available && (
                <div className="rounded-md border border-blue-500/30 bg-blue-500/10 p-3 text-sm text-blue-700 dark:text-blue-300">
                  {plan?.decision === "manual_review_required"
                    ? "Manual review required — no automated corrective action is available for this case."
                    : "Evidence collected only — no corrective remediation was applied or generated."}
                </div>
              )}
              {plan?.next_manual_steps && plan.next_manual_steps.length > 0 && (
                <div>
                  <div className="text-sm font-medium mb-2">Next Manual Steps</div>
                  <div className="space-y-2">
                    {plan.next_manual_steps.map((step, i) => (
                      <div key={i} className="text-sm bg-accent/30 rounded-md p-2">{step}</div>
                    ))}
                  </div>
                </div>
              )}
              {plan?.corrective_actions && plan.corrective_actions.length > 0 && (
                <div>
                  <div className="text-sm font-medium mb-2">Corrective Actions</div>
                  <pre className="bg-muted rounded-lg p-4 text-xs overflow-auto max-h-[260px] whitespace-pre-wrap">
                    {JSON.stringify(plan.corrective_actions, null, 2)}
                  </pre>
                </div>
              )}
              {plan?.rollback_actions && plan.rollback_actions.length > 0 && (
                <div>
                  <div className="text-sm font-medium mb-2 flex items-center gap-2">
                    <RotateCcw className="h-4 w-4" />
                    Rollback
                  </div>
                  <pre className="bg-muted rounded-lg p-4 text-xs overflow-auto max-h-[220px] whitespace-pre-wrap">
                    {JSON.stringify(plan.rollback_actions, null, 2)}
                  </pre>
                </div>
              )}
              {playbookSummary?.remediation_playbook_yaml ? (
                <pre className="bg-muted rounded-lg p-4 text-xs overflow-auto max-h-[600px] whitespace-pre-wrap">
                  {playbookSummary.remediation_playbook_yaml}
                </pre>
              ) : (
                <div className="text-center text-muted-foreground py-8">
                  No remediation playbook is available for this planner decision.
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="verification" className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-primary" />
                Verification
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {inv.verification?.status ? (
                <>
                  <DetailRow label="Status" value={inv.verification.status.replace(/_/g, " ")} />
                  <DetailRow label="New Alerts" value={(inv.verification.new_alerts_found ?? 0).toString()} mono />
                  <p className="text-sm text-muted-foreground whitespace-pre-wrap">{inv.verification.detail}</p>
                </>
              ) : (
                <div className="text-sm text-muted-foreground">
                  No remediation verification has run. Verification is only meaningful after real corrective action is approved and executed.
                </div>
              )}
              {plan?.verification_checks && plan.verification_checks.length > 0 && (
                <div>
                  <div className="text-sm font-medium mb-2">Planned Checks</div>
                  <div className="space-y-2">
                    {plan.verification_checks.map((check, i) => (
                      <div key={i} className="text-sm bg-accent/30 rounded-md p-2">{check}</div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="timeline" className="space-y-4">
          <RuntimeTimeline investigationId={id} />
        </TabsContent>

        <TabsContent value="raw" className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <FileCode className="h-4 w-4 text-primary" />
                Raw Investigation Data
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <pre className="bg-muted rounded-lg p-4 text-xs overflow-auto max-h-[360px] whitespace-pre-wrap">
                {JSON.stringify(
                  {
                    remediation_plan: inv.remediation_plan,
                    diagnostic_output: inv.diagnostic_output,
                    alert_payloads: inv.alert_payloads,
                    run: inv.run,
                    verification: inv.verification,
                  },
                  null,
                  2
                )}
              </pre>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start gap-2">
      <span className="text-xs text-muted-foreground w-24 shrink-0">{label}</span>
      <span className={cn("text-sm", mono && "font-mono break-all")}>{value}</span>
    </div>
  );
}

function ConfidenceBadge({ confidence }: { confidence: number }) {
  let label = "Low";
  let color = "bg-slate-500/10 text-slate-500 border-slate-500/20";
  if (confidence >= 0.95) { label = "Very High"; color = "bg-emerald-500/10 text-emerald-500 border-emerald-500/20"; }
  else if (confidence >= 0.85) { label = "High"; color = "bg-blue-500/10 text-blue-500 border-blue-500/20"; }
  else if (confidence >= 0.70) { label = "Medium"; color = "bg-amber-500/10 text-amber-500 border-amber-500/20"; }
  return (
    <Badge variant="outline" className={cn("text-xs", color)}>
      Confidence: {label} ({(confidence * 100).toFixed(0)}%)
    </Badge>
  );
}

function PriorityBadge({ priority }: { priority: number }) {
  const colors: Record<number, string> = {
    1: "bg-red-500/10 text-red-500 border-red-500/20",
    2: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    3: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  };
  return (
    <Badge variant="outline" className={cn("text-xs", colors[priority] || colors[3])}>
      P{priority}
    </Badge>
  );
}

function EvidenceItem({ label, value, mono, status }: { label: string; value: string; mono?: boolean; status?: "ok" | "warning" | "neutral" }) {
  const statusColor =
    status === "ok"
      ? "text-emerald-600"
      : status === "warning"
      ? "text-amber-600"
      : "text-foreground";
  return (
    <div className="rounded-md border p-2.5">
      <div className="text-xs text-muted-foreground uppercase tracking-wide">{label}</div>
      <div className={cn("text-sm font-medium mt-0.5", mono && "font-mono break-all", statusColor)}>{value}</div>
    </div>
  );
}

function RuntimeTimeline({ investigationId }: { investigationId: string }) {
  const { data } = useSWR(
    `runtime-timeline-${investigationId}`,
    () => runtimeAPI.getTimeline(investigationId)
  );
  const events = data?.events || [];

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <History className="h-4 w-4 text-primary" />
          Timeline
        </CardTitle>
      </CardHeader>
      <CardContent>
        {events.length === 0 ? (
          <div className="text-center text-muted-foreground py-8">No timeline events</div>
        ) : (
          <div className="space-y-4">
            {events.map((event: any, i: number) => (
              <div key={i} className="flex items-start gap-3">
                <div className="mt-1">
                  {event.type === "created" && <CheckCircle2 className="h-4 w-4 text-emerald-500" />}
                  {event.type === "diagnosing" && <Activity className="h-4 w-4 text-amber-500" />}
                  {event.type === "findings_ready" && <Eye className="h-4 w-4 text-blue-500" />}
                  {event.type === "acknowledged" && <ThumbsUp className="h-4 w-4 text-emerald-500" />}
                  {event.type === "escalated" && <AlertTriangle className="h-4 w-4 text-rose-500" />}
                  {event.type === "approved" && <ShieldCheck className="h-4 w-4 text-blue-500" />}
                  {event.type === "running" && <Play className="h-4 w-4 text-amber-500" />}
                  {event.type === "completed" && <CheckCircle2 className="h-4 w-4 text-emerald-500" />}
                  {event.type === "failed" && <XCircle className="h-4 w-4 text-destructive" />}
                  {!["created","diagnosing","findings_ready","acknowledged","escalated","approved","running","completed","failed"].includes(event.type) && (
                    <Clock className="h-4 w-4 text-muted-foreground" />
                  )}
                </div>
                <div>
                  <div className="text-sm font-medium capitalize">{event.type.replace(/_/g, " ")}</div>
                  <div className="text-xs text-muted-foreground">{event.description}</div>
                  {event.timestamp && (
                    <div className="text-xs text-muted-foreground mt-0.5">
                      {formatAbsoluteDateTime(event.timestamp)}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
