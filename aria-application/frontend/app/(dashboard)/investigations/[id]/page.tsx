"use client";

import { use, useState, useCallback, useEffect } from "react";
import useSWR from "swr";
import { useRouter } from "next/navigation";
import { format } from "date-fns";
import { formatAbsoluteDateTime } from "@/lib/time";
import { getAdminSecret, setAdminSecret, clearAdminSecret, hasAdminSecret, AdminSecretRequiredError } from "@/lib/admin-secret";
import { AdminSecretDialog } from "@/components/admin-secret-dialog";
import {
  ArrowLeft,
  Brain,
  Clock,
  Target,
  Shield,
  Archive,
  ChevronRight,
  AlertTriangle,
  Server,
  Globe,
  CheckCircle2,
  XCircle,
  Play,
  Copy,
  Monitor,
  Search,
  Bug,
  RotateCcw,
  Layers,
  Terminal,
  Eye,
  FileText,
  HardDrive,
  FolderOpen,
  Info,
} from "lucide-react";
import {
  investigationsAPI,
  assetsAPI,
  type Investigation,
  type InvestigationTimeline,
  type MonitoredAsset,
} from "@/lib/api";
import { useWSSubscription, type WSMessage } from "@/lib/websocket";
import { PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { RichAlertEvidence } from "@/components/rich-alert-evidence";
import { RiskAssessmentCard } from "@/components/risk-assessment-card";
import { AttackNarrativeCard } from "@/components/attack-narrative-card";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";

import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";

function getEventConfig(type: string) {
  const configs: Record<string, { color: string; label: string }> = {
    created: { color: "bg-primary", label: "Created" },
    incident_created: { color: "bg-primary", label: "Incident Created" },
    ai_started: { color: "bg-blue-500", label: "AI Started" },
    ai_analysis: { color: "bg-blue-500", label: "AI Analysis" },
    ai_analysis_complete: { color: "bg-blue-500", label: "AI Analysis" },
    ai_completed: { color: "bg-emerald-500", label: "AI Completed" },
    playbook_generated: { color: "bg-blue-500", label: "Playbook Generated" },
    awaiting_approval: { color: "bg-warning", label: "Awaiting Approval" },
    approved: { color: "bg-emerald-500", label: "Approved" },
    declined: { color: "bg-destructive", label: "Declined" },
    remediation_started: { color: "bg-blue-500", label: "Remediation Started" },
    running: { color: "bg-blue-500", label: "Running" },
    playbook_approved: { color: "bg-blue-500", label: "Execution Started" },
    remediation_completed: { color: "bg-emerald-500", label: "Remediation Complete" },
    completed: { color: "bg-emerald-500", label: "Completed" },
    completed_with_warnings: { color: "bg-warning", label: "Completed (Warnings)" },
    failed: { color: "bg-destructive", label: "Failed" },
    verified: { color: "bg-emerald-500", label: "Verified" },
    verification_complete: { color: "bg-emerald-500", label: "Verified" },
    verification_failed: { color: "bg-destructive", label: "Verification Failed" },
    archived: { color: "bg-muted-foreground", label: "Archived" },
    alerts_linked: { color: "bg-primary", label: "Alerts Linked" },
    critical_alerts: { color: "bg-destructive", label: "Critical Alerts" },
    investigation_created: { color: "bg-primary", label: "Investigation Created" },
  };
  return configs[type] || { color: "bg-muted-foreground", label: type };
}

function parseSourceIps(sourceIps: string | string[] | null | undefined): string[] {
  if (Array.isArray(sourceIps)) return sourceIps;
  if (typeof sourceIps === "string") return sourceIps.split(",").map((s) => s.trim()).filter(Boolean);
  return [];
}

const PHASE_ORDER = ["evidence", "dry_run", "containment", "hardening", "forensics", "verification"];

const PHASE_META: Record<string, { label: string; icon: React.ElementType }> = {
  evidence: { label: "Evidence", icon: Search },
  dry_run: { label: "Dry Run", icon: Eye },
  containment: { label: "Containment", icon: Shield },
  hardening: { label: "Hardening", icon: Layers },
  forensics: { label: "Forensics", icon: Bug },
  verification: { label: "Verification", icon: CheckCircle2 },
  rollback: { label: "Rollback", icon: RotateCcw },
};

const STAGE_ICON_META: Record<string, React.ElementType> = {
  incident_selected: Target,
  evidence_collection: Search,
  ai_root_cause: Brain,
  remediation_planning: FileText,
  approval: Shield,
  execution: Terminal,
  verification: CheckCircle2,
  completed: CheckCircle2,
  archived: Archive,
};

function WorkflowProgress({ workflow }: { workflow: Investigation["workflow"] }) {
  if (!workflow?.stages?.length) return null;

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-primary" />
          <CardTitle className="text-base font-medium">SOC Workflow</CardTitle>
          {workflow.current_stage && (
            <StatusBadge status={workflow.current_stage.status} className="text-xs" />
          )}
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid gap-2 md:grid-cols-3 xl:grid-cols-9">
          {workflow.stages.map((stage) => {
            const StageIcon = STAGE_ICON_META[stage.key] || Layers;
            const state = stage.status;
            return (
              <div
                key={stage.key}
                className={cn(
                  "min-h-[112px] rounded-md border p-3",
                  state === "completed" && "border-success/30 bg-success/5",
                  state === "current" && "border-primary/40 bg-primary/5 ring-1 ring-primary/20",
                  state === "failed" && "border-destructive/30 bg-destructive/5",
                  state === "blocked" && "border-destructive/30 bg-destructive/5",
                  state === "not_applicable" && "bg-muted/30",
                  state === "pending" && "bg-muted/30"
                )}
              >
                <div className="flex items-center gap-2">
                  <StageIcon className={cn(
                    "h-4 w-4",
                    state === "completed" && "text-success",
                    state === "current" && "text-primary",
                    state === "failed" && "text-destructive",
                    state === "blocked" && "text-destructive",
                    state === "not_applicable" && "text-muted-foreground",
                    state === "pending" && "text-muted-foreground"
                  )} />
                  <span className="text-xs font-medium leading-tight">{stage.label}</span>
                </div>
                <StatusBadge status={state} className="mt-2 text-xs" />
                {stage.details && (
                  <p className="mt-2 line-clamp-3 text-xs text-muted-foreground">
                    {stage.details}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

function PhaseProgress({
  phases,
  currentPhase,
  runStatus,
  runOutput,
}: {
  phases: Record<string, any>;
  currentPhase?: string | null;
  runStatus?: string;
  runOutput?: string;
}) {
  const [selectedPhase, setSelectedPhase] = useState<string | null>(null);

  const phaseList = PHASE_ORDER.map((key) => {
    const meta = PHASE_META[key] || { label: key, icon: Layers };
    const info = phases[key] || {};
    const isCurrent = currentPhase === key;
    const isDone = info.status === "completed" || info.status === "success";
    const isFailed = info.status === "failed" || info.status === "error";
    const isPending = !isDone && !isFailed && !isCurrent;
    const hasOutput = !!info.output_preview || !!info.output;
    return { key, ...meta, isCurrent, isDone, isFailed, isPending, hasOutput, info };
  });

  const rollbackInfo = phases["rollback"] || {};
  const hasRollback = rollbackInfo.status || phases["rollback"];
  const hasAnyPhaseData = PHASE_ORDER.some((k) => phases[k]?.status);

  const effectiveSelected = selectedPhase || (currentPhase && phases[currentPhase] ? currentPhase : null);
  const selectedInfo = effectiveSelected ? phases[effectiveSelected] : null;

  const isFailedBeforePhases = runStatus === "failed" && !hasAnyPhaseData;

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-primary" />
          <CardTitle className="text-base font-medium">Execution Phases</CardTitle>
          {currentPhase && (
            <StatusBadge status={currentPhase} className="text-xs" />
          )}
          {isFailedBeforePhases && (
            <StatusBadge status="failed" className="text-xs" />
          )}
        </div>
      </CardHeader>
      <CardContent>
        {isFailedBeforePhases && (
          <div className="mb-3 rounded-md border border-destructive/30 bg-destructive/5 p-3">
            <div className="flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-destructive mt-0.5 shrink-0" />
              <div className="space-y-1">
                <p className="text-sm font-medium text-destructive">
                  Execution failed before any phase could start
                </p>
                {runOutput && (
                  <pre className="text-xs font-mono text-destructive/90 whitespace-pre-wrap">
                    {runOutput}
                  </pre>
                )}
                <p className="text-xs text-muted-foreground">
                  Common causes: SSH unreachable, authentication failure, missing Ansible inventory, or target host offline.
                </p>
              </div>
            </div>
          </div>
        )}
        <div className="flex items-center gap-2 overflow-x-auto pb-2">
          {phaseList.map((phase, index) => (
            <div key={phase.key} className="flex items-center gap-2 shrink-0">
              {(() => {
                const PhaseIcon = phase.icon;
                const isSelected = effectiveSelected === phase.key;
                return (
                  <button
                    onClick={() => phase.hasOutput && setSelectedPhase(phase.key)}
                    className={cn(
                      "flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-all",
                      phase.hasOutput && "cursor-pointer hover:brightness-95",
                      !phase.hasOutput && "cursor-default",
                      isSelected && "ring-2 ring-offset-1",
                      phase.isCurrent && "bg-primary/10 text-primary border-primary/40 ring-primary",
                      phase.isDone && "bg-success/10 text-success border-success/30 ring-success",
                      phase.isFailed && "bg-destructive/10 text-destructive border-destructive/30 ring-destructive",
                      phase.isPending && "bg-muted text-muted-foreground border-border ring-muted-foreground"
                    )}
                  >
                    <PhaseIcon className="h-3 w-3" />
                    {phase.label}
                    {phase.isCurrent && <span className="ml-0.5 h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />}
                    {phase.isDone && <CheckCircle2 className="ml-0.5 h-3 w-3" />}
                    {phase.isFailed && <XCircle className="ml-0.5 h-3 w-3" />}
                  </button>
                );
              })()}
              {index < phaseList.length - 1 && (
                <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />
              )}
            </div>
          ))}
          {hasRollback && (
            <>
              <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />
              <button
                onClick={() => rollbackInfo.output_preview && setSelectedPhase("rollback")}
                className={cn(
                  "flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-all",
                  rollbackInfo.output_preview && "cursor-pointer hover:brightness-95",
                  !rollbackInfo.output_preview && "cursor-default",
                  effectiveSelected === "rollback" && "ring-2 ring-destructive ring-offset-1",
                  currentPhase === "rollback"
                    ? "bg-destructive/10 text-destructive border-destructive/40"
                    : "bg-muted text-muted-foreground border-border"
                )}
              >
                <RotateCcw className="h-3 w-3" />
                Rollback
                {currentPhase === "rollback" && <span className="ml-0.5 h-1.5 w-1.5 rounded-full bg-destructive animate-pulse" />}
              </button>
            </>
          )}
        </div>

        {/* Selected phase detail panel */}
        {effectiveSelected && selectedInfo && (
          <div className="mt-3 rounded-md border p-3 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">
                  {PHASE_META[effectiveSelected]?.label || effectiveSelected} Details
                </span>
                {selectedInfo.status && (
                  <Badge variant="outline" className={cn(
                    "text-xs",
                    selectedInfo.status === "completed" && "bg-success/10 text-success border-success/30",
                    selectedInfo.status === "failed" && "bg-destructive/10 text-destructive border-destructive/30",
                  )}>
                    {selectedInfo.status}
                  </Badge>
                )}
                {typeof selectedInfo.exit_code === "number" && (
                  <Badge variant="outline" className="text-xs font-mono">
                    exit {selectedInfo.exit_code}
                  </Badge>
                )}
              </div>
              {selectedInfo.finished_at && (
                <span className="text-xs text-muted-foreground">
                  {(() => {
                    const d = new Date(selectedInfo.finished_at);
                    return !isNaN(d.getTime()) ? format(d, "HH:mm:ss") : "";
                  })()}
                </span>
              )}
            </div>
            {(selectedInfo.output_preview || selectedInfo.output) && (
              <ScrollArea className="h-[300px] rounded-md bg-muted">
                <pre className="p-3 text-xs font-mono text-muted-foreground whitespace-pre-wrap">
                  {selectedInfo.output_preview || selectedInfo.output}
                </pre>
              </ScrollArea>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function InvestigationDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const router = useRouter();
  const [showDeclineDialog, setShowDeclineDialog] = useState(false);
  const [declineReason, setDeclineReason] = useState("");
  const [showRegenerateDialog, setShowRegenerateDialog] = useState(false);
  const [regenerateReason, setRegenerateReason] = useState("");
  const [showReviewedDialog, setShowReviewedDialog] = useState(false);
  const [reviewedReason, setReviewedReason] = useState("");
  const [showRollbackDialog, setShowRollbackDialog] = useState(false);
  const [rollbackReason, setRollbackReason] = useState("");
  const [isActioning, setIsActioning] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [showAdminSecretDialog, setShowAdminSecretDialog] = useState(false);
  const [pendingAction, setPendingAction] = useState<"execute" | "rollback" | null>(null);
  const [runStatus, setRunStatus] = useState<{
    status: string;
    exit_code?: number | null;
    output?: string;
    current_phase?: string;
    phases?: Record<string, any>;
  } | null>(null);

  const { data: investigation, error, isLoading, mutate } = useSWR(
    ["investigation", id],
    () => investigationsAPI.get(id),
    { refreshInterval: (data) => (data?.status === "running" ? 5000 : 0) }
  );

  const { data: timeline, error: timelineError } = useSWR(
    ["investigation-timeline", id],
    () => investigationsAPI.getTimeline(id)
  );

  const { data: evidenceFiles } = useSWR(
    ["investigation-evidence-files", id],
    () => investigationsAPI.getEvidenceFiles(id),
    { revalidateOnFocus: false }
  );

  // Fetch target asset details for remediation preview
  const { data: targetAsset } = useSWR<MonitoredAsset>(
    investigation?.asset_id ? ["investigation-target-asset", investigation.asset_id] : null,
    () => assetsAPI.get(investigation!.asset_id!),
    { revalidateOnFocus: false }
  );

  // Poll run-status when investigation is running
  useEffect(() => {
    if (investigation?.status !== "running") {
      setRunStatus(null);
      return;
    }
    let cancelled = false;
    const poll = async () => {
      try {
        const status = await investigationsAPI.getRunStatus(id);
        if (!cancelled) {
          setRunStatus(status);
        }
      } catch {
        // ignore polling errors
      }
    };
    poll();
    const interval = setInterval(poll, 3000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [investigation?.status, id]);

  const handleWSUpdate = useCallback(
    (message: WSMessage) => {
      mutate();
    },
    [mutate]
  );

  useWSSubscription("investigation_updated", handleWSUpdate);

  const handleApprove = async () => {
    setIsActioning(true);
    setActionError(null);
    try {
      await investigationsAPI.approve(id, "admin");
      mutate();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setActionError(message);
      console.error("Failed to approve investigation:", error);
    } finally {
      setIsActioning(false);
    }
  };

  const handleDecline = async () => {
    setIsActioning(true);
    setActionError(null);
    try {
      await investigationsAPI.decline(id, "admin", declineReason);
      mutate();
      setShowDeclineDialog(false);
      setDeclineReason("");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setActionError(message);
      console.error("Failed to decline investigation:", error);
    } finally {
      setIsActioning(false);
    }
  };

  const handleRequestRegeneration = async () => {
    setIsActioning(true);
    setActionError(null);
    try {
      await investigationsAPI.requestRegeneration(id, "admin", regenerateReason);
      mutate();
      setShowRegenerateDialog(false);
      setRegenerateReason("");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setActionError(message);
      console.error("Failed to request regeneration:", error);
    } finally {
      setIsActioning(false);
    }
  };

  const handleMarkReviewed = async () => {
    setIsActioning(true);
    setActionError(null);
    try {
      await investigationsAPI.markReviewed(id, "admin", reviewedReason);
      mutate();
      setShowReviewedDialog(false);
      setReviewedReason("");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setActionError(message);
      console.error("Failed to mark as reviewed:", error);
    } finally {
      setIsActioning(false);
    }
  };

  const [adminSecretDialogError, setAdminSecretDialogError] = useState<string | null>(null);

  const isAdminSecretError = (message: string) =>
    message.includes("403") || message.includes("Admin action requires") || message.includes("Invalid admin secret");

  const handleExecute = async () => {
    setIsActioning(true);
    setActionError(null);
    try {
      await investigationsAPI.execute(id);
      mutate();
    } catch (error) {
      if (error instanceof AdminSecretRequiredError) {
        setPendingAction("execute");
        setShowAdminSecretDialog(true);
        return;
      }
      const message = error instanceof Error ? error.message : String(error);
      if (isAdminSecretError(message)) {
        clearAdminSecret();
        setPendingAction("execute");
        setAdminSecretDialogError(message);
        setShowAdminSecretDialog(true);
      } else {
        setActionError(message);
      }
    } finally {
      setIsActioning(false);
    }
  };


  const handleRollback = async () => {
    if (rollbackReason.length < 10) return;
    setIsActioning(true);
    setActionError(null);
    try {
      await investigationsAPI.rollback(id, "admin", rollbackReason);
      mutate();
      setShowRollbackDialog(false);
      setRollbackReason("");
    } catch (error) {
      if (error instanceof AdminSecretRequiredError) {
        setPendingAction("rollback");
        setShowAdminSecretDialog(true);
        return;
      }
      const message = error instanceof Error ? error.message : String(error);
      if (isAdminSecretError(message)) {
        clearAdminSecret();
        setPendingAction("rollback");
        setAdminSecretDialogError(message);
        setShowAdminSecretDialog(true);
      } else {
        setActionError(message);
      }
    } finally {
      setIsActioning(false);
    }
  };

  const handleAdminSecretConfirm = (secret: string) => {
    setAdminSecret(secret);
    setAdminSecretDialogError(null);
    setShowAdminSecretDialog(false);
    const action = pendingAction;
    setPendingAction(null);
    if (action === "execute") handleExecute();
    if (action === "rollback") handleRollback();
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
      </div>
    );
  }

  if (error || !investigation) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader
          title="Investigation"
          description="Unable to load investigation details"
          onRefresh={() => mutate()}
        />
        <div className="flex-1 flex items-center justify-center p-6">
          <Card className="border-destructive/50 bg-destructive/5 max-w-md">
            <CardContent className="flex flex-col items-center gap-3 py-8">
              <AlertTriangle className="h-10 w-10 text-destructive" />
              <p className="font-medium text-destructive text-center">Failed to load investigation</p>
              <p className="text-sm text-muted-foreground text-center">
                {error instanceof Error ? error.message : "Please try again later."}
              </p>
              <Button variant="outline" onClick={() => mutate()}>
                Retry
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  const data = investigation;
  const timelineEvents = timeline?.events || [];

  const executionMode = data.execution_mode || "none";
  const hasRemediation = data.has_remediation_action === true;

  const sourceIps = parseSourceIps(data.source_ips);
  const canonicalIncidentId = data.local_incident_id || data.incident_id;

  return (
    <div className="flex flex-col">
      <PageHeader
        title={data.incident_title}
        description={`Investigation for incident ${data.incident_id}`}
        onRefresh={() => mutate()}
        backHref="/investigations"
        actions={
          <div className="flex items-center gap-2">
            {data.asset_id && targetAsset && !targetAsset.remediation_enabled && (
              <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-1.5 mr-2">
                Remediation disabled for <strong>{targetAsset.name}</strong>.{" "}
                <a
                  href={`/settings/assets?edit=${targetAsset.asset_id}`}
                  className="underline hover:text-red-800"
                >
                  Enable in Settings →
                </a>
              </div>
            )}
            {(data.analyst_actions || []).includes("approve") && (
              <Button onClick={handleApprove} disabled={isActioning}>
                <CheckCircle2 className="mr-2 h-4 w-4" />
                Approve Playbook
              </Button>
            )}
            {(data.analyst_actions || []).includes("decline") && (
              <Button
                variant="destructive"
                onClick={() => setShowDeclineDialog(true)}
                disabled={isActioning}
              >
                <XCircle className="mr-2 h-4 w-4" />
                Decline
              </Button>
            )}
            {(data.analyst_actions || []).includes("request_regeneration") && (
              <Button
                variant="secondary"
                onClick={() => setShowRegenerateDialog(true)}
                disabled={isActioning}
              >
                <RotateCcw className="mr-2 h-4 w-4" />
                Regenerate
              </Button>
            )}
            {(data.analyst_actions || []).includes("mark_reviewed") && (
              <Button
                variant="outline"
                onClick={() => setShowReviewedDialog(true)}
                disabled={isActioning}
              >
                <Eye className="mr-2 h-4 w-4" />
                Mark Reviewed
              </Button>
            )}
            {(data.analyst_actions || []).includes("archive") && (
              <Button
                variant="outline"
                onClick={async () => {
                  setIsActioning(true);
                  try {
                    await investigationsAPI.archive(id);
                    mutate();
                  } catch (error) {
                    setActionError(error instanceof Error ? error.message : String(error));
                  } finally {
                    setIsActioning(false);
                  }
                }}
                disabled={isActioning}
              >
                <Archive className="mr-2 h-4 w-4" />
                Archive
              </Button>
            )}
            {(data.analyst_actions || []).includes("execute") && (
              <Button onClick={() => handleExecute()} disabled={isActioning}>
                <Play className="mr-2 h-4 w-4" />
                Execute Playbook
              </Button>
            )}
            {(data.admin_actions || []).includes("rollback") && (
              <Button
                variant="outline"
                className="border-orange-500 text-orange-600 hover:bg-orange-50"
                onClick={() => setShowRollbackDialog(true)}
                disabled={isActioning}
              >
                <RotateCcw className="mr-2 h-4 w-4" />
                Rollback
              </Button>
            )}
            <Button variant="outline" onClick={() => router.back()}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
            {hasAdminSecret() && (
              <Badge variant="outline" className="text-emerald-600 border-emerald-300 gap-1">
                <Shield className="h-3 w-3" />
                Admin
              </Badge>
            )}
          </div>
        }
      />

      <div className="flex-1 space-y-6 p-6">
        {/* Safety / Execution Mode Banner */}
        {executionMode === "diagnostic_only" && (
          <Card className="border-blue-500/50 bg-blue-500/5">
            <CardContent className="flex items-start gap-3 py-4">
              <Eye className="h-5 w-5 text-blue-500 shrink-0 mt-0.5" />
              <div className="min-w-0">
                <p className="font-medium text-blue-600">Read-only Diagnostic</p>
                <p className="text-sm text-muted-foreground">
                  This investigation contains a diagnostic-only playbook with no remediation actions. No approval or execution is required.
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Manual Review Banner */}
        {data.status === "manual_review_required" && (
          <Card className="border-amber-500/50 bg-amber-500/5">
            <CardContent className="flex items-start gap-3 py-4">
              <Eye className="h-5 w-5 text-amber-500 shrink-0 mt-0.5" />
              <div className="min-w-0">
                <p className="font-medium text-amber-600">Manual Review Required</p>
                <p className="text-sm text-muted-foreground">
                  This case requires analyst validation before any action can be taken.
                  Review the evidence, AI analysis, and truth report to determine the
                  appropriate next steps.
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Completed / Archived Banner */}
        {(data.status === "completed" || data.status === "archived") && (
          <Card className="border-emerald-500/50 bg-emerald-500/5">
            <CardContent className="flex items-start gap-3 py-4">
              <CheckCircle2 className="h-5 w-5 text-emerald-500 shrink-0 mt-0.5" />
              <div className="min-w-0">
                <p className="font-medium text-emerald-600">
                  {data.status === "archived" ? "Archived" : "Completed"}
                </p>
                <p className="text-sm text-muted-foreground">
                  {data.status === "archived"
                    ? "This investigation has been archived. No further actions are available."
                    : "This investigation has been completed. Review the verification result and archive when ready."}
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Awaiting Approval / Evidence Banner */}
        {data.status === "awaiting_approval" && !data.has_remediation_action && (
          <Card className="border-blue-500/50 bg-blue-500/5">
            <CardContent className="flex items-start gap-3 py-4">
              <Info className="h-5 w-5 text-blue-500 shrink-0 mt-0.5" />
              <div className="min-w-0">
                <p className="font-medium text-blue-600">Awaiting Evidence</p>
                <p className="text-sm text-muted-foreground">
                  This investigation is waiting for additional evidence or analyst
                  review. No executable remediation plan is available yet.
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Execution Reliability Banner */}
        {data.status === "completed_with_warnings" && (
          <Card className="border-warning/50 bg-warning/5">
            <CardContent className="flex items-start gap-3 py-4">
              <AlertTriangle className="h-5 w-5 text-warning shrink-0 mt-0.5" />
              <div className="min-w-0">
                <p className="font-medium text-warning">Completed with Warnings</p>
                <p className="text-sm text-muted-foreground">
                  Remediation finished but optional phases failed:{" "}
                  {(data.warning_phases || []).join(", ")}.
                  The mandatory phases (evidence, containment, verification) succeeded.
                </p>
              </div>
            </CardContent>
          </Card>
        )}
        {data.status === "failed" && data.failed_phase && (
          <Card className="border-destructive/50 bg-destructive/5">
            <CardContent className="flex items-start gap-3 py-4">
              <XCircle className="h-5 w-5 text-destructive shrink-0 mt-0.5" />
              <div className="min-w-0">
                <p className="font-medium text-destructive">Failed at {data.failed_phase} phase</p>
                <p className="text-sm text-muted-foreground">
                  A mandatory phase failed during execution. The remediation was not completed.
                  Review the phase output below for details.
                </p>
              </div>
            </CardContent>
          </Card>
        )}
        {/* AI Quality Banner */}
        {data.ai_quality_status === "failed" && (
          <Card className="border-destructive/50 bg-destructive/5">
            <CardContent className="flex items-start gap-3 py-4">
              <Brain className="h-5 w-5 text-destructive shrink-0 mt-0.5" />
              <div className="min-w-0">
                <p className="font-medium text-destructive">AI Quality Failed</p>
                <p className="text-sm text-muted-foreground">
                  The AI-generated summary failed quality checks (hallucinations, missing evidence, or empty output).
                  This investigation requires manual review before approval.
                </p>
              </div>
            </CardContent>
          </Card>
        )}
        {data.ai_quality_status === "weak" && (
          <Card className="border-amber-500/50 bg-amber-500/5">
            <CardContent className="flex items-start gap-3 py-4">
              <Brain className="h-5 w-5 text-amber-500 shrink-0 mt-0.5" />
              <div className="min-w-0">
                <p className="font-medium text-amber-600">AI Quality Weak</p>
                <p className="text-sm text-muted-foreground">
                  The AI summary has weak evidence grounding or uses fallback analysis.
                  Verify findings before approving.
                </p>
              </div>
            </CardContent>
          </Card>
        )}
        {/* Action Error */}
        {actionError && (
          <Card className="border-destructive/50 bg-destructive/5">
            <CardContent className="flex items-center gap-3 py-4">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              <div>
                <p className="font-medium text-destructive">Action failed</p>
                <p className="text-sm text-muted-foreground">{actionError}</p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Status Bar */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7">
          <Card>
            <CardContent className="pt-6">
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">Status</p>
                <StatusBadge status={data.status} />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">Severity</p>
                <SeverityBadge severity={data.incident_severity || "medium"} />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">AI Quality</p>
                <StatusBadge
                  status={
                    data.ai_quality_status === "passed"
                      ? "verified"
                      : data.ai_quality_status === "failed"
                      ? "failed"
                      : data.ai_quality_status === "weak"
                      ? "degraded"
                      : "unknown"
                  }
                />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="space-y-1.5 min-w-0">
                <p className="text-sm text-muted-foreground">Target Host</p>
                <Badge variant="secondary" className="max-w-full">
                  <Server className="mr-1 h-3 w-3 shrink-0" />
                  <span className="truncate">{data.target_host || "Unknown"}</span>
                </Badge>
              </div>
            </CardContent>
          </Card>
          {data.asset_id && targetAsset && (
            <Card>
              <CardContent className="pt-6">
                <div className="space-y-1.5 min-w-0">
                  <p className="text-sm text-muted-foreground">Target Asset</p>
                  <Badge variant="outline" className="text-xs max-w-full">
                    <Server className="mr-1 h-3 w-3 shrink-0" />
                    <span className="truncate">{targetAsset.name} ({targetAsset.asset_id})</span>
                  </Badge>
                  <div className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-xs">
                    <span className={targetAsset.remediation_enabled ? "text-emerald-600" : "text-red-600"}>
                      {targetAsset.remediation_enabled ? "Remediation enabled" : "Remediation disabled"}
                    </span>
                    <span className="text-muted-foreground">|</span>
                    <span className="text-muted-foreground break-all">
                      {(targetAsset.ansible_config_json as any)?.ansible_host || targetAsset.hostname || "No host"}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
          <Card>
            <CardContent className="pt-6">
              <div className="space-y-1.5 min-w-0">
                <p className="text-sm text-muted-foreground">Target OS</p>
                <Badge variant="outline" className="max-w-full">
                  <Monitor className="mr-1 h-3 w-3 shrink-0" />
                  <span className="truncate">{data.target_os || "Unknown"}</span>
                </Badge>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="space-y-1.5 min-w-0">
                <p className="text-sm text-muted-foreground">Incident</p>
                <Badge
                  variant="outline"
                  className="cursor-pointer font-mono max-w-full"
                  onClick={() => router.push(`/incidents/${canonicalIncidentId}`)}
                >
                  <span className="truncate">{canonicalIncidentId}</span>
                  <ChevronRight className="ml-1 h-3 w-3 shrink-0" />
                </Badge>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Started</p>
                  <p className="text-sm font-medium">
                    {formatAbsoluteDateTime(data.created_at)}
                  </p>
                </div>
                <Clock className="h-8 w-8 text-muted-foreground/50" />
              </div>
            </CardContent>
          </Card>
        </div>

        <WorkflowProgress workflow={data.workflow} />

        {/* Phase Progress */}
        {(data.run?.phases || runStatus?.phases || data.run?.status === "failed" || runStatus?.status === "failed") && (
          <PhaseProgress
            phases={runStatus?.phases || data.run?.phases || {}}
            currentPhase={runStatus?.current_phase || data.run?.current_phase}
            runStatus={runStatus?.status || data.run?.status}
            runOutput={runStatus?.output || data.run?.output}
          />
        )}

        {/* Source IPs */}
        {sourceIps.length > 0 && (
          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <Globe className="h-4 w-4 text-warning" />
                <CardTitle className="text-base font-medium">
                  Attacking IPs ({sourceIps.length})
                </CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {sourceIps.map((ip, index) => (
                  <Badge
                    key={index}
                    variant="outline"
                    className="font-mono cursor-pointer hover:bg-accent"
                    onClick={() => router.push(`/search?q=${ip}`)}
                  >
                    {ip}
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-4 w-4 ml-1 p-0"
                      onClick={(e) => {
                        e.stopPropagation();
                        copyToClipboard(ip);
                      }}
                    >
                      <Copy className="h-3 w-3" />
                    </Button>
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        <Tabs defaultValue="analysis" className="space-y-4">
          <TabsList>
            <TabsTrigger value="analysis">AI Analysis</TabsTrigger>
            <TabsTrigger value="evidence">Evidence</TabsTrigger>
            <TabsTrigger value="playbook">Playbook</TabsTrigger>
            <TabsTrigger value="timeline">Timeline</TabsTrigger>
          </TabsList>

          <TabsContent value="analysis" className="space-y-4">
            {/* Summary */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Brain className="h-5 w-5 text-primary" />
                  <CardTitle className="text-base font-medium">AI Summary</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                {data.ai_error ? (
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-destructive mt-0.5" />
                    <p className="text-destructive">{data.ai_error}</p>
                  </div>
                ) : (
                  <p className="text-muted-foreground whitespace-pre-wrap">
                    {data.ai_summary || "AI analysis in progress..."}
                  </p>
                )}
              </CardContent>
            </Card>

            {/* Truth Report */}
            {data.truth_report && (
              <Card className="border-emerald-500/30">
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <Shield className="h-5 w-5 text-emerald-500" />
                    <CardTitle className="text-base font-medium">Truth Report</CardTitle>
                    <Badge variant="outline" className="text-xs">
                      {data.truth_report.confidence}
                    </Badge>
                    <Badge
                      variant={
                        data.truth_report.final_classification === "confirmed_threat"
                          ? "destructive"
                          : data.truth_report.final_classification === "suspected_threat"
                          ? "default"
                          : "outline"
                      }
                      className="text-xs"
                    >
                      {data.truth_report.final_classification}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  {data.truth_report.observed_facts.length > 0 && (
                    <div>
                      <p className="text-sm font-medium text-emerald-600 mb-1">Observed Facts</p>
                      <ul className="text-sm text-muted-foreground list-disc list-inside space-y-0.5">
                        {data.truth_report.observed_facts.map((fact, i) => (
                          <li key={i}>{fact}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {data.truth_report.inferred_findings.length > 0 && (
                    <div>
                      <p className="text-sm font-medium text-blue-600 mb-1">Inferred Findings</p>
                      <ul className="text-sm text-muted-foreground list-disc list-inside space-y-0.5">
                        {data.truth_report.inferred_findings.map((finding, i) => (
                          <li key={i}>{finding}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {data.truth_report.unsupported_claims.length > 0 && (
                    <div>
                      <p className="text-sm font-medium text-destructive mb-1">Unsupported Claims</p>
                      <ul className="text-sm text-muted-foreground list-disc list-inside space-y-0.5">
                        {data.truth_report.unsupported_claims.map((claim, i) => (
                          <li key={i}>{claim}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {data.truth_report.recommended_next_steps.length > 0 && (
                    <div>
                      <p className="text-sm font-medium text-amber-600 mb-1">Recommended Next Steps</p>
                      <ul className="text-sm text-muted-foreground list-disc list-inside space-y-0.5">
                        {data.truth_report.recommended_next_steps.map((step, i) => (
                          <li key={i}>{step}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div className="flex items-center gap-2 pt-2 border-t">
                    <p className="text-xs text-muted-foreground">
                      Evidence quality: <span className="font-medium">{data.truth_report.evidence_quality}</span>
                    </p>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Risk Assessment & Attack Narrative */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              {data.ai_risk && <RiskAssessmentCard text={data.ai_risk} />}
              {data.ai_narrative && <AttackNarrativeCard text={data.ai_narrative} />}
            </div>
          </TabsContent>

          <TabsContent value="evidence" className="space-y-4">
            {data.alerts && data.alerts.length > 0 && (
              <Card>
                <CardHeader className="pb-2">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-warning" />
                    <CardTitle className="text-base font-medium">
                      Alert Evidence ({data.alerts.length})
                    </CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {data.alerts.map((alert) => (
                      <div key={alert.alert_id} className="rounded-md border p-3">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <SeverityBadge severity={alert.severity || "medium"} />
                              <Badge variant="outline" className="text-xs">{alert.source || "unknown"}</Badge>
                              {alert.rule_name && (
                                <Badge variant="secondary" className="max-w-[260px] truncate text-xs">
                                  {alert.rule_name}
                                </Badge>
                              )}
                            </div>
                            <p className="mt-2 font-medium">{alert.title || alert.alert_id}</p>
                            {alert.description && (
                              <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">
                                {alert.description}
                              </p>
                            )}
                          </div>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => router.push(`/alerts?id=${alert.alert_id}`)}
                          >
                            View Alert
                            <ChevronRight className="ml-1 h-3 w-3" />
                          </Button>
                        </div>
                        <div className="mt-3 grid gap-2 text-xs md:grid-cols-3">
                          <div>
                            <span className="text-muted-foreground">Source IP</span>
                            <p className="font-mono">{alert.source_ip || "—"}</p>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Destination IP</span>
                            <p className="font-mono">{alert.dest_ip || "—"}</p>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Host</span>
                            <p className="font-mono">{alert.hostname || "—"}</p>
                          </div>
                        </div>
                        {alert.tags && alert.tags.length > 0 && (
                          <div className="mt-3 flex flex-wrap gap-1">
                            {alert.tags.slice(0, 8).map((tag, tidx) => (
                              <Badge key={`${tag}-${tidx}`} variant="secondary" className="text-xs">
                                {tag}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Rich Suricata / Filebeat Evidence */}
            {data.alerts && data.alerts.some((a) => a.metadata && Object.keys(a.metadata).length > 0) && (
              <Card>
                <CardHeader className="pb-2">
                  <div className="flex items-center gap-2">
                    <Search className="h-5 w-5 text-primary" />
                    <CardTitle className="text-base font-medium">Rich Alert Metadata</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  <RichAlertEvidence alerts={data.alerts} />
                </CardContent>
              </Card>
            )}

            {/* Remediation-Stage Evidence (collected by Ansible during evidence phase) */}
            {data.evidence_json ? (
              <>
                <Card>
                  <CardHeader>
                    <div className="flex items-center gap-2">
                      <HardDrive className="h-5 w-5 text-primary" />
                      <CardTitle className="text-base font-medium">Remediation-Stage Evidence</CardTitle>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="grid gap-3 md:grid-cols-2">
                      <div className="flex items-center gap-2 text-sm">
                        <Clock className="h-4 w-4 text-muted-foreground" />
                        <span className="text-muted-foreground">Collected:</span>
                        <span className="font-medium">
                          {formatAbsoluteDateTime(data.evidence_json.collected_at)}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-sm">
                        <CheckCircle2 className="h-4 w-4 text-success" />
                        <span className="text-muted-foreground">Exit Code:</span>
                        <Badge variant="outline" className="text-xs font-mono">
                          {data.evidence_json.exit_code ?? "N/A"}
                        </Badge>
                      </div>
                      {data.evidence_json.path && (
                        <div className="flex items-center gap-2 text-sm">
                          <Server className="h-4 w-4 text-muted-foreground" />
                          <span className="text-muted-foreground">Target Path:</span>
                          <span className="font-mono text-xs">{data.evidence_json.path}</span>
                        </div>
                      )}
                      {data.evidence_json.local_path && (
                        <div className="flex items-center gap-2 text-sm">
                          <HardDrive className="h-4 w-4 text-muted-foreground" />
                          <span className="text-muted-foreground">Local Path:</span>
                          <span className="font-mono text-xs">{data.evidence_json.local_path}</span>
                        </div>
                      )}
                      {data.evidence_json.archive_path && (
                        <div className="flex items-center gap-2 text-sm md:col-span-2">
                          <FolderOpen className="h-4 w-4 text-muted-foreground" />
                          <span className="text-muted-foreground">Archive:</span>
                          <span className="font-mono text-xs">{data.evidence_json.archive_path}</span>
                          {evidenceFiles?.archive_exists && (
                            <Badge variant="outline" className="text-xs bg-success/10 text-success">
                              {(() => {
                                const bytes = evidenceFiles.archive_size_bytes || 0;
                                if (bytes > 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
                                if (bytes > 1024) return `${(bytes / 1024).toFixed(1)} KB`;
                                return `${bytes} B`;
                              })()}
                            </Badge>
                          )}
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>

                {/* Evidence Files */}
                {evidenceFiles && evidenceFiles.files && evidenceFiles.files.length > 0 && (
                  <Card>
                    <CardHeader className="pb-2">
                      <div className="flex items-center gap-2">
                        <FileText className="h-5 w-5 text-primary" />
                        <CardTitle className="text-base font-medium">
                          Evidence Files ({evidenceFiles.file_count})
                        </CardTitle>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="rounded-md border">
                        <div className="grid grid-cols-12 gap-2 border-b bg-muted px-3 py-2 text-xs font-medium text-muted-foreground">
                          <div className="col-span-6">File</div>
                          <div className="col-span-3">Size</div>
                          <div className="col-span-3">Modified</div>
                        </div>
                        {evidenceFiles.files.map((file, idx) => (
                          <div
                            key={idx}
                            className="grid grid-cols-12 gap-2 px-3 py-2 text-sm border-b last:border-0 items-center"
                          >
                            <div className="col-span-6 flex items-center gap-2">
                              <FileText className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                              <span className="font-mono text-xs truncate" title={file.relative_path}>
                                {file.name}
                              </span>
                            </div>
                            <div className="col-span-3 text-xs text-muted-foreground">
                              {(() => {
                                const bytes = file.size_bytes;
                                if (bytes > 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
                                if (bytes > 1024) return `${(bytes / 1024).toFixed(1)} KB`;
                                return `${bytes} B`;
                              })()}
                            </div>
                            <div className="col-span-3 text-xs text-muted-foreground">
                              {(() => {
                                const d = new Date(file.modified_at);
                                return !isNaN(d.getTime()) ? format(d, "HH:mm:ss") : "—";
                              })()}
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Raw JSON (collapsible) */}
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">Raw Evidence Metadata</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <pre className="rounded-lg bg-muted p-3 text-xs font-mono overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(data.evidence_json, null, 2)}
                    </pre>
                  </CardContent>
                </Card>
              </>
            ) : (
              <Card>
                <CardContent className="py-8 text-center">
                  <HardDrive className="mx-auto h-10 w-10 text-muted-foreground/50" />
                  <p className="mt-3 text-muted-foreground">
                    No remediation-stage evidence collected yet.
                  </p>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Evidence gathered during the Ansible Evidence Collection phase will appear here.
                  </p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="playbook">
            {data.playbook_summary && (
              <Card className="mb-4">
                <CardHeader>
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <Shield className="h-5 w-5 text-primary" />
                      <CardTitle className="text-base font-medium">Playbook Review Summary</CardTitle>
                    </div>
                    <div className="flex items-center gap-2">
                      {data.playbook_summary.high_impact && (
                        <Badge variant="outline" className="border-warning/40 bg-warning/10 text-warning">
                          High impact
                        </Badge>
                      )}
                      {data.playbook_summary.requires_approval && (
                        <Badge variant="outline">Approval required</Badge>
                      )}
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-3 md:grid-cols-2">
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">Why it is needed</p>
                      <p className="mt-1 text-sm">{data.playbook_summary.why_needed}</p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">Target</p>
                      <p className="mt-1 font-mono text-sm">{data.playbook_summary.target}</p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">Expected impact</p>
                      <p className="mt-1 text-sm">{data.playbook_summary.expected_impact}</p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">Rollback</p>
                      <p className="mt-1 text-sm">{data.playbook_summary.rollback_summary}</p>
                    </div>
                  </div>
                  {data.playbook_summary.what_it_will_do.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">Actions</p>
                      <div className="mt-2 grid gap-2 md:grid-cols-2">
                        {data.playbook_summary.what_it_will_do.map((task, idx) => (
                          <div key={`${task}-${idx}`} className="rounded-md border bg-muted/30 px-3 py-2 text-sm">
                            {task}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {data.playbook_summary.verification_checks.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">Verification checks</p>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {data.playbook_summary.verification_checks.map((check, idx) => (
                          <Badge key={`${check}-${idx}`} variant="secondary">
                            {check}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base font-medium">Ansible Playbook</CardTitle>
                  <div className="flex items-center gap-2">
                    {data.playbook_valid ? (
                      <Badge variant="outline" className="bg-emerald-500/10 text-emerald-500">
                        <CheckCircle2 className="mr-1 h-3 w-3" />
                        Valid YAML
                      </Badge>
                    ) : data.ai_error ? (
                      <Badge variant="outline" className="bg-destructive/10 text-destructive">
                        <XCircle className="mr-1 h-3 w-3" />
                        Invalid
                      </Badge>
                    ) : null}
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => copyToClipboard(data.playbook_yaml || "")}
                    >
                      <Copy className="mr-1 h-3 w-3" />
                      Copy
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                {data.playbook_yaml ? (
                  <ScrollArea className="h-[500px]">
                    <pre className="rounded-lg bg-muted p-4 text-sm font-mono overflow-x-auto">
                      {data.playbook_yaml}
                    </pre>
                  </ScrollArea>
                ) : data.ai_error ? (
                  <div className="py-12 text-center">
                    <AlertTriangle className="mx-auto h-12 w-12 text-destructive/50" />
                    <p className="mt-4 text-destructive font-medium">
                      Playbook generation failed
                    </p>
                    <p className="mt-2 text-sm text-muted-foreground max-w-md mx-auto">
                      {data.ai_error}
                    </p>
                  </div>
                ) : (
                  <div className="py-12 text-center">
                    <Brain className="mx-auto h-12 w-12 text-muted-foreground/50 animate-pulse" />
                    <p className="mt-4 text-muted-foreground">
                      AI is generating the playbook...
                    </p>
                  </div>
                )}
                {data.ai_error && (
                  <div className="mt-4 p-4 rounded-lg bg-destructive/10 border border-destructive/30">
                    <p className="text-sm text-destructive">{data.ai_error}</p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Rollback Playbook */}
            {data.rollback_playbook && (
              <Card className="mt-4 border-destructive/30">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <RotateCcw className="h-5 w-5 text-destructive" />
                      <CardTitle className="text-base font-medium">Rollback Playbook</CardTitle>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => copyToClipboard(data.rollback_playbook || "")}
                    >
                      <Copy className="mr-1 h-3 w-3" />
                      Copy
                    </Button>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    Generated automatically during containment. Reverts containment actions if needed.
                  </p>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[300px]">
                    <pre className="rounded-lg bg-muted p-4 text-sm font-mono overflow-x-auto">
                      {data.rollback_playbook}
                    </pre>
                  </ScrollArea>
                </CardContent>
              </Card>
            )}

            {/* Post-Rollback Verification */}
            {data.post_rollback_verification_json && (
              <Card className="mt-4 border-orange-500/30">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="h-5 w-5 text-orange-500" />
                      <CardTitle className="text-base font-medium">Post-Rollback Verification</CardTitle>
                    </div>
                    <StatusBadge
                      status={
                        data.post_rollback_verification_json.status === "passed"
                          ? "verified"
                          : data.post_rollback_verification_json.status === "failed"
                          ? "failed"
                          : "unknown"
                      }
                    />
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid gap-2 md:grid-cols-2">
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">Command</p>
                      <p className="mt-1 font-mono text-xs">{data.post_rollback_verification_json.command}</p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">Exit Code</p>
                      <p className="mt-1 font-mono text-sm">{data.post_rollback_verification_json.exit_code}</p>
                    </div>
                    {data.post_rollback_verification_json.timestamp && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground">Timestamp</p>
                        <p className="mt-1 text-sm">
                          {format(new Date(data.post_rollback_verification_json.timestamp), "yyyy-MM-dd HH:mm:ss")}
                        </p>
                      </div>
                    )}
                  </div>
                  {data.post_rollback_verification_json.stdout && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">Output</p>
                      <pre className="mt-1 rounded-lg bg-muted p-3 text-xs font-mono overflow-x-auto whitespace-pre-wrap">
                        {data.post_rollback_verification_json.stdout}
                      </pre>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="timeline">
            <Card>
              <CardHeader>
                <CardTitle className="text-base font-medium">Investigation Timeline</CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[400px] pr-4">
                  <div className="relative space-y-4 pl-6">
                    <div className="absolute left-2 top-2 h-[calc(100%-16px)] w-px bg-border" />
                    {timelineEvents.length === 0 && !timelineError && (
                      <p className="text-sm text-muted-foreground">No timeline events yet.</p>
                    )}
                    {timelineError && (
                      <p className="text-sm text-destructive">Failed to load timeline events.</p>
                    )}
                    {timelineEvents.map((event, index) => {
                      const eventType = event.event || event.type || "";
                      const config = getEventConfig(eventType);
                      return (
                        <div key={index} className="relative">
                          <div
                            className={cn(
                              "absolute -left-6 top-1 h-3 w-3 rounded-full border-2 border-background",
                              config.color
                            )}
                          />
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className="text-xs">
                                {config.label}
                              </Badge>
                              {event.severity && event.severity !== "info" && (
                                <Badge variant="secondary" className="text-xs">
                                  {event.severity}
                                </Badge>
                              )}
                            </div>
                            {(event.details || event.description) && (
                              <p className="text-sm">{event.details || event.description}</p>
                            )}
                            <p className="text-xs text-muted-foreground">
                              {event.timestamp
                                ? (() => {
                                    const d = new Date(event.timestamp);
                                    return !isNaN(d.getTime()) ? format(d, "PPpp") : "—";
                                  })()
                                : "—"}
                            </p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>

      {/* Decline Dialog */}
      <Dialog open={showDeclineDialog} onOpenChange={setShowDeclineDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Decline Investigation</DialogTitle>
            <DialogDescription>
              Provide a reason for declining this investigation. The case will be queued for archive.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <Textarea
              placeholder="Reason for declining (optional)..."
              value={declineReason}
              onChange={(e) => setDeclineReason(e.target.value)}
              rows={3}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDeclineDialog(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleDecline} disabled={isActioning}>
              <XCircle className="mr-2 h-4 w-4" />
              Decline Investigation
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Request Regeneration Dialog */}
      <Dialog open={showRegenerateDialog} onOpenChange={setShowRegenerateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Request Playbook Regeneration</DialogTitle>
            <DialogDescription>
              The AI will re-analyze the incident and generate a new playbook. Provide a reason to guide the regeneration.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <Textarea
              placeholder="Reason for regeneration (e.g., playbook unsafe, missing rollback, incorrect analysis)..."
              value={regenerateReason}
              onChange={(e) => setRegenerateReason(e.target.value)}
              rows={3}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRegenerateDialog(false)}>
              Cancel
            </Button>
            <Button variant="secondary" onClick={handleRequestRegeneration} disabled={isActioning}>
              <RotateCcw className="mr-2 h-4 w-4" />
              Request Regeneration
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Mark Reviewed Dialog */}
      <Dialog open={showReviewedDialog} onOpenChange={setShowReviewedDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Mark as Reviewed — No Action</DialogTitle>
            <DialogDescription>
              Mark this investigation as reviewed with no remediation action required. The case can be archived later.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <Textarea
              placeholder="Reason for no action (optional)..."
              value={reviewedReason}
              onChange={(e) => setReviewedReason(e.target.value)}
              rows={3}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowReviewedDialog(false)}>
              Cancel
            </Button>
            <Button variant="outline" onClick={handleMarkReviewed} disabled={isActioning}>
              <Eye className="mr-2 h-4 w-4" />
              Mark Reviewed
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rollback Dialog */}
      <Dialog open={showRollbackDialog} onOpenChange={setShowRollbackDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rollback Remediation</DialogTitle>
            <DialogDescription>
              This will execute the rollback playbook to reverse the remediation actions applied to the target host.
              <span className="block mt-2 text-orange-600 font-medium">
                Only use this when you need to undo a completed remediation.
              </span>
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <Textarea
              placeholder="Reason for rollback (required, min 10 chars)..."
              value={rollbackReason}
              onChange={(e) => setRollbackReason(e.target.value)}
              rows={3}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRollbackDialog(false)}>
              Cancel
            </Button>
            <Button
              className="bg-orange-600 hover:bg-orange-700"
              onClick={() => handleRollback()}
              disabled={isActioning || rollbackReason.length < 10}
            >
              <RotateCcw className="mr-2 h-4 w-4" />
              Confirm Rollback
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Admin Secret Dialog */}
      <AdminSecretDialog
        open={showAdminSecretDialog}
        onOpenChange={(open) => {
          setShowAdminSecretDialog(open);
          if (!open) setAdminSecretDialogError(null);
        }}
        onConfirm={handleAdminSecretConfirm}
        error={adminSecretDialogError}
      />
    </div>
  );
}
