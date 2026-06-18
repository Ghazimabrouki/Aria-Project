"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import useSWR, { mutate as globalMutate } from "swr";
import { formatDistanceToNow } from "date-fns";
import {
  Send,
  Bot,
  User,
  Loader2,
  Terminal,
  ShieldAlert,
  Play,
  Clock,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronRight,
  Plus,
  Trash2,
  AlertTriangle,
  Sparkles,
  Server,
  HardDrive,
  MemoryStick,
  Activity,
  Globe,
  Copy,
  Check,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { PageHeader } from "@/components/page-header";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { riskClasses } from "@/lib/ui-status";
import { useSelectedAsset } from "@/lib/asset-context";
import { useAuth } from "@/lib/auth-context";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { AIChatInput } from "@/components/ui/ai-chat-input";
import {
  operatorAPI,
  assetsAPI,
  type OperatorSession,
  type OperatorSessionDetail,
  type OperatorMessage,
} from "@/lib/api";

// ── Types ───────────────────────────────────────────────────────────────────

interface LocalMessage extends OperatorMessage {
  isStreaming?: boolean;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// Risk badge classes — delegates to the shared design-token scale so risk
// colors stay consistent with severity badges across the app. Unknown/empty
// risk falls back to "low" (the prior default behavior).
function riskBadgeColor(level?: string) {
  return riskClasses(level ?? "low");
}

function statusIcon(status?: string) {
  switch (status) {
    case "completed":
      return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    case "failed":
      return <XCircle className="h-4 w-4 text-red-500" />;
    case "running":
      return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />;
    case "pending_approval":
      return <Clock className="h-4 w-4 text-amber-500" />;
    default:
      return null;
  }
}

// ── Components ──────────────────────────────────────────────────────────────

function ReasoningCard({ content }: { content: string }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="rounded-lg border border-border/60 bg-muted/30 p-3">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="flex items-center gap-2 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors"
      >
        {expanded ? (
          <ChevronDown className="h-3.5 w-3.5" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5" />
        )}
        <Sparkles className="h-3.5 w-3.5" />
        AI Reasoning
      </button>
      {expanded && (
        <p className="mt-2 text-xs text-muted-foreground whitespace-pre-wrap leading-relaxed">
          {content}
        </p>
      )}
    </div>
  );
}

function ExecutionSummaryCard({
  summary,
  playbookYaml,
  destructiveActions,
  estimatedDuration,
  riskLevel,
  steps,
}: {
  summary: string;
  playbookYaml?: string;
  destructiveActions?: string[];
  estimatedDuration?: string;
  riskLevel?: string;
  steps?: string[];
}) {
  const [showRaw, setShowRaw] = useState(false);
  const hasDestructive = (destructiveActions?.length ?? 0) > 0;

  return (
    <div className="rounded-lg border bg-card p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Server className="h-4 w-4 text-primary" />
          <span className="text-sm font-medium">Execution Plan</span>
        </div>
        <div className="flex items-center gap-2">
          {estimatedDuration && (
            <span className="text-xs text-muted-foreground">
              ~{estimatedDuration}
            </span>
          )}
          <Badge variant="outline" className={cn("text-xs", riskBadgeColor(riskLevel))}>
            {riskLevel?.toUpperCase() ?? "MEDIUM"} RISK
          </Badge>
        </div>
      </div>

      {hasDestructive && (
        <div className="flex items-start gap-2 rounded-md bg-red-500/5 border border-red-500/20 p-2.5">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
          <div className="space-y-0.5">
            <p className="text-xs font-medium text-red-600 dark:text-red-400">
              Destructive actions detected
            </p>
            <ul className="text-xs text-muted-foreground list-disc list-inside">
              {destructiveActions!.map((a, i) => (
                <li key={i}>{a}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <div className="space-y-1">
        {steps && steps.length > 0 ? (
          steps.map((step, i) => (
            <div key={i} className="flex items-start gap-2 text-sm">
              <span className="mt-0.5 h-5 w-5 rounded-full bg-primary/10 text-primary flex items-center justify-center text-xs font-bold shrink-0">
                {i + 1}
              </span>
              <span className="text-foreground/90">{step}</span>
            </div>
          ))
        ) : (
          <div className="text-sm text-muted-foreground whitespace-pre-line">
            {summary}
          </div>
        )}
      </div>

      {playbookYaml && (
        <button
          onClick={() => setShowRaw((v) => !v)}
          className="text-xs text-muted-foreground hover:text-foreground underline underline-offset-2"
        >
          {showRaw ? "Hide raw playbook" : "Show raw playbook"}
        </button>
      )}
      {showRaw && playbookYaml && (
        <pre className="bg-black/5 dark:bg-white/5 rounded p-2 text-xs overflow-x-auto max-h-40 border">
          {playbookYaml}
        </pre>
      )}
    </div>
  );
}

function ParsedDataCard({ parsed }: { parsed: NonNullable<OperatorMessage["result"]>["parsed_data"] }) {
  if (!parsed) return null;

  return (
    <div className="space-y-3">
      {/* Disk Usage */}
      {parsed.disk_usage && parsed.disk_usage.length > 0 && (
        <div className="rounded-md border bg-card/50 p-3 space-y-2">
          <p className="text-xs font-semibold text-foreground/80 flex items-center gap-1.5">
            <HardDrive className="h-3.5 w-3.5 text-primary" />
            Disk Usage
          </p>
          <div className="space-y-1">
            {parsed.disk_usage.map((d, i) => (
              <div key={i} className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground truncate max-w-[50%]" title={d.mounted_on}>
                  {d.mounted_on}
                </span>
                <div className="flex items-center gap-2">
                  <span className="font-mono">{d.used} / {d.size}</span>
                  <span className={cn(
                    "px-1.5 py-0.5 rounded text-xs font-medium",
                    parseInt(d.use_percent) > 90 ? "bg-red-500/15 text-red-600" :
                    parseInt(d.use_percent) > 70 ? "bg-amber-500/15 text-amber-600" :
                    "bg-green-500/15 text-green-600"
                  )}>
                    {d.use_percent}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Memory Usage */}
      {parsed.memory_usage?.mem && (
        <div className="rounded-md border bg-card/50 p-3 space-y-2">
          <p className="text-xs font-semibold text-foreground/80 flex items-center gap-1.5">
            <MemoryStick className="h-3.5 w-3.5 text-primary" />
            Memory
          </p>
          <div className="grid grid-cols-3 gap-2 text-center">
            <div className="rounded bg-primary/5 p-2">
              <p className="text-xs text-muted-foreground">Total</p>
              <p className="text-sm font-semibold">{parsed.memory_usage.mem.total}</p>
            </div>
            <div className="rounded bg-primary/5 p-2">
              <p className="text-xs text-muted-foreground">Used</p>
              <p className="text-sm font-semibold">{parsed.memory_usage.mem.used}</p>
            </div>
            <div className="rounded bg-green-500/10 p-2">
              <p className="text-xs text-muted-foreground">Available</p>
              <p className="text-sm font-semibold text-green-600">{parsed.memory_usage.mem.available || parsed.memory_usage.mem.free}</p>
            </div>
          </div>
          {parsed.memory_usage.swap && (
            <p className="text-xs text-muted-foreground text-center">
              Swap: {parsed.memory_usage.swap.used} / {parsed.memory_usage.swap.total}
            </p>
          )}
        </div>
      )}

      {/* Top Processes */}
      {parsed.top_processes && parsed.top_processes.length > 0 && (
        <div className="rounded-md border bg-card/50 p-3 space-y-2">
          <p className="text-xs font-semibold text-foreground/80 flex items-center gap-1.5">
            <Activity className="h-3.5 w-3.5 text-primary" />
            Top Processes
          </p>
          <div className="space-y-1">
            {parsed.top_processes.slice(0, 10).map((p, i) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                <span className="font-mono text-xs w-8 text-right text-muted-foreground">{p.pid}</span>
                <span className="flex-1 truncate font-medium" title={p.command}>{p.command}</span>
                <span className="font-mono text-xs w-10 text-right">{p.cpu}% CPU</span>
                <span className="font-mono text-xs w-10 text-right">{p.mem}% MEM</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Service Status */}
      {parsed.service_status && (
        <div className="rounded-md border bg-card/50 p-3 space-y-1">
          <p className="text-xs font-semibold text-foreground/80">Service: {parsed.service_status.service}</p>
          <div className="flex items-center gap-2">
            <span className={cn(
              "h-2 w-2 rounded-full",
              parsed.service_status.active_state === "active" ? "bg-green-500" : "bg-red-500"
            )} />
            <span className="text-xs">{parsed.service_status.status_text}</span>
          </div>
        </div>
      )}
    </div>
  );
}

function RollbackCard({ rollback }: { rollback: NonNullable<OperatorMessage["result"]>["rollback"] }) {
  const [copied, setCopied] = useState(false);
  if (!rollback) return null;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(rollback.command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore
    }
  };

  return (
    <details className="rounded-md border border-border/60 bg-muted/30 p-3 text-xs">
      <summary className="cursor-pointer font-medium text-muted-foreground hover:text-foreground list-none flex items-center gap-2">
        <ChevronRight className="h-3.5 w-3.5 details-open:rotate-90 transition-transform" />
        <span>Rollback command</span>
        <Badge variant="outline" className="text-xs ml-1">
          {rollback.risk_level}
        </Badge>
      </summary>
      <div className="mt-2 space-y-1.5">
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">{rollback.action}</span>
          <button
            onClick={handleCopy}
            className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors"
          >
            {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
        <pre className="bg-black/5 dark:bg-white/5 rounded p-2 overflow-x-auto whitespace-pre-wrap text-xs font-mono border">
          {rollback.command}
        </pre>
        <p className="text-muted-foreground">
          Target: {rollback.target_host} ({rollback.target_ip})
        </p>
      </div>
    </details>
  );
}

function MessageTimestamp({ createdAt }: { createdAt?: string }) {
  if (!createdAt) return null;
  try {
    const date = new Date(createdAt);
    if (isNaN(date.getTime())) return null;
    return (
      <p className="text-xs text-muted-foreground mt-1">
        {formatDistanceToNow(date, { addSuffix: true })}
      </p>
    );
  } catch {
    return null;
  }
}

function ResultCard({ result }: { result: OperatorMessage["result"] }) {
  if (!result) return null;
  const analysis = result.analysis;
  const parsed = result.parsed_data;
  const failedTasks = parsed?.failed_tasks ?? [];
  const unreachableHosts = parsed?.unreachable_hosts ?? [];
  const hasFailedTasks = failedTasks.length > 0;
  const hasUnreachableHosts = unreachableHosts.length > 0;
  const outcome = hasFailedTasks || hasUnreachableHosts
    ? "failure"
    : (analysis?.outcome ?? (result.exit_code === 0 ? "success" : "failure"));

  return (
    <div
      className={cn(
        "rounded-lg border p-4 space-y-3",
        outcome === "success"
          ? "bg-green-500/5 border-green-500/20"
          : outcome === "partial"
          ? "bg-amber-500/5 border-amber-500/20"
          : "bg-red-500/5 border-red-500/20"
      )}
    >
      <div className="flex items-center gap-2">
        {outcome === "success" ? (
          <CheckCircle2 className="h-4 w-4 text-green-500" />
        ) : outcome === "partial" ? (
          <AlertTriangle className="h-4 w-4 text-amber-500" />
        ) : (
          <XCircle className="h-4 w-4 text-red-500" />
        )}
        <span className="text-sm font-medium">
          {outcome === "success"
            ? "Execution Successful"
            : outcome === "partial"
            ? "Partial Success"
            : "Execution Failed"}
        </span>
        <span className="text-xs text-muted-foreground ml-auto">
          Exit code {result.exit_code}
        </span>
      </div>

      {/* Raw Ansible output — always show on failure so user sees the real error */}
      {result.output && (
        <details className="text-xs">
          <summary className="cursor-pointer text-muted-foreground hover:text-foreground font-medium">
            Raw Ansible output
          </summary>
          <pre className="mt-1 p-2 bg-muted rounded-md overflow-auto max-h-60 whitespace-pre-wrap text-xs">
            {result.output}
          </pre>
        </details>
      )}

      {/* Failed tasks */}
      {hasFailedTasks && (
        <div className="space-y-1">
          <p className="text-xs font-medium text-red-600">Failed Tasks</p>
          <ul className="text-xs text-foreground/80 list-disc list-inside space-y-0.5">
            {failedTasks.map((t: any, i: number) => (
              <li key={i}>
                {t.name ?? t.task ?? "Unknown task"}
                {t.host && <span className="text-muted-foreground"> on {t.host}</span>}
                {t.error && <span className="text-red-600"> — {t.error}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Unreachable hosts */}
      {hasUnreachableHosts && (
        <div className="space-y-1">
          <p className="text-xs font-medium text-red-600">Unreachable Hosts</p>
          <ul className="text-xs text-foreground/80 list-disc list-inside space-y-0.5">
            {unreachableHosts.map((h: any, i: number) => (
              <li key={i}>{h.host ?? h} {h.error && `— ${h.error}`}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Structured parsed data */}
      {parsed && <ParsedDataCard parsed={parsed} />}

      {analysis?.explanation && (
        <p className="text-sm text-foreground/90 leading-relaxed">
          {analysis.explanation}
        </p>
      )}

      {analysis?.key_changes && analysis.key_changes.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">Key Changes</p>
          <ul className="text-xs text-foreground/80 list-disc list-inside space-y-0.5">
            {analysis.key_changes.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
        </div>
      )}

      {analysis?.recommendations && analysis.recommendations.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">Recommendations</p>
          <ul className="text-xs text-foreground/80 list-disc list-inside space-y-0.5">
            {analysis.recommendations.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}

      {result.rollback && <RollbackCard rollback={result.rollback} />}
    </div>
  );
}

// ── Main Page ───────────────────────────────────────────────────────────────

export default function OperatorPage() {
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [currentStep, setCurrentStep] = useState<string>("");
  const [targetHosts, setTargetHosts] = useState("");
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [sessionToDelete, setSessionToDelete] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const operatorPlaceholders = [
    "Your infrastructure deserves better observability",
    "Check disk usage on the target host",
    "Block IP 10.0.0.5 on the firewall",
    "Restart nginx and verify it's running",
    "Clean up old log files older than 30 days",
    "Analyze memory usage trends",
  ];
  const { toast } = useToast();
  const { selectedAssetId, setSelectedAssetId, assets } = useSelectedAsset();
  const { user } = useAuth();

  // Auto-select locked asset for server_user accounts
  useEffect(() => {
    if (user?.role === "server_user" && user?.asset_id && !selectedAssetId) {
      setSelectedAssetId(user.asset_id);
    }
  }, [user, selectedAssetId, setSelectedAssetId]);

  // Fetch asset readiness for remediation banner
  const { data: assetReadiness } = useSWR(
    selectedAssetId ? ["operator-asset-readiness", selectedAssetId] : null,
    () => assetsAPI.getAnsible(selectedAssetId!).then(r => r.readiness)
  );

  // Polling interval for run status
  const [pollingRunId, setPollingRunId] = useState<string | null>(null);

  // Fetch available inventory hosts
  const { data: inventoryData } = useSWR(
    "operator-inventory-hosts",
    () => operatorAPI.listInventoryHosts(),
    { refreshInterval: 60000 }
  );
  const inventoryHosts = inventoryData?.hosts ?? [];
  const inventoryState = inventoryData?.state ?? "unknown";
  const inventoryMessage = inventoryData?.message ?? "";
  const hasInventory = inventoryData?.has_inventory ?? false;
  const validForExecution = inventoryData?.valid_for_execution ?? false;

  const inventoryStatusText = (() => {
    if (inventoryState === "missing") return "No valid Ansible inventory found";
    if (inventoryState === "unreadable") return "Ansible inventory is unreadable";
    if (inventoryState === "malformed") return "Ansible inventory is malformed";
    if (inventoryState === "empty") return "No reachable Ansible targets found";
    if (!hasInventory || inventoryHosts.length === 0) return "No reachable Ansible targets found";
    return "";
  })();

  // Fetch sessions list
  const { data: sessionsData, mutate: mutateSessions } = useSWR(
    "operator-sessions",
    () => operatorAPI.listSessions(50),
    { refreshInterval: 30000 }
  );

  // Fetch active session detail
  const { data: sessionDetail, mutate: mutateSession } = useSWR(
    activeSessionId ? ["operator-session", activeSessionId] : null,
    () => operatorAPI.getSession(activeSessionId!),
    { refreshInterval: pollingRunId ? 3000 : 10000 }
  );

  // Poll run status separately for faster updates
  const { data: runStatus } = useSWR(
    pollingRunId ? ["operator-run-status", pollingRunId] : null,
    () => operatorAPI.getRunStatus(pollingRunId!),
    { refreshInterval: 3000 }
  );

  // Auto-scroll only when new messages arrive (not on every SWR revalidation)
  const prevMessageCountRef = useRef(0);
  useEffect(() => {
    const count = sessionDetail?.messages?.length ?? 0;
    if (scrollRef.current && count > prevMessageCountRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
    prevMessageCountRef.current = count;
  }, [sessionDetail?.messages]);

  // Stop polling when run completes
  useEffect(() => {
    if (runStatus && runStatus.status !== "running") {
      setPollingRunId(null);
      mutateSession();
    }
  }, [runStatus, mutateSession]);

  // Sync target hosts bar with selected session
  useEffect(() => {
    if (sessionDetail?.target_hosts) {
      setTargetHosts(sessionDetail.target_hosts.join(","));
    }
  }, [sessionDetail?.target_hosts]);

  // Derive target hosts from selected asset (mutually exclusive with All servers)
  // Resolve inventory alias when possible; fallback to ansible_host / hostname / ip / asset_id
  useEffect(() => {
    if (selectedAssetId && assets.length > 0 && !activeSessionId) {
      const asset = assets.find((a) => a.asset_id === selectedAssetId);
      if (asset) {
        const ansibleHost = (asset.ansible_config_json as any)?.ansible_host;
        const match = inventoryHosts.find(
          (h) =>
            h.host === ansibleHost ||
            h.host === asset.hostname ||
            h.host === asset.ip_address ||
            h.alias === asset.asset_id ||
            h.alias === asset.hostname
        );
        const target = match?.alias || ansibleHost || asset.hostname || asset.ip_address || asset.asset_id;
        setTargetHosts(target);
      }
    }
  }, [selectedAssetId, assets, activeSessionId, inventoryHosts]);

  const handleCreateSession = async () => {
    // Re-compute target from current asset/inventory to avoid stale state race condition
    let hosts: string[] = [];
    if (selectedAssetId && assets.length > 0) {
      const asset = assets.find((a) => a.asset_id === selectedAssetId);
      if (asset) {
        const ansibleHost = (asset.ansible_config_json as any)?.ansible_host;
        const match = inventoryHosts.find(
          (h) =>
            h.host === ansibleHost ||
            h.host === asset.hostname ||
            h.host === asset.ip_address ||
            h.alias === asset.asset_id ||
            h.alias === asset.hostname
        );
        const target = match?.alias || ansibleHost || asset.hostname || asset.ip_address || asset.asset_id;
        if (target) hosts = [target];
      }
    }
    if (!hosts.length) {
      hosts = targetHosts.split(",").map((h) => h.trim()).filter(Boolean);
    }
    if (!validForExecution || hosts.length === 0) {
      toast({ title: "No targets", description: inventoryStatusText || "Select at least one Ansible target host.", variant: "destructive" });
      return;
    }
    try {
      const session = await operatorAPI.createSession({
        title: "New Session",
        target_hosts: hosts,
        asset_id: selectedAssetId || undefined,
      });
      setActiveSessionId(session.id);
      globalMutate("operator-sessions");
    } catch (err: any) {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    }
  };

  const promptDeleteSession = (id: string) => {
    setSessionToDelete(id);
    setDeleteDialogOpen(true);
  };

  const handleDeleteSession = async () => {
    if (!sessionToDelete) return;
    try {
      await operatorAPI.deleteSession(sessionToDelete);
      if (activeSessionId === sessionToDelete) setActiveSessionId(null);
      globalMutate("operator-sessions");
    } catch (err: any) {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    } finally {
      setDeleteDialogOpen(false);
      setSessionToDelete(null);
    }
  };

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;
    if (!activeSessionId) {
      toast({ title: "No session", description: "Create a session first", variant: "destructive" });
      return;
    }

    const prompt = input.trim();
    setInput("");
    setIsLoading(true);
    setCurrentStep("Analyzing intent and planning...");

    try {
      const data = await operatorAPI.sendMessage(activeSessionId, prompt, true, selectedAssetId || undefined);
      mutateSession();

      if (data.status === "running") {
        setPollingRunId(data.run_id);
        setCurrentStep("Executing on target host...");
      } else if (data.status === "pending_approval") {
        setCurrentStep("Waiting for approval...");
      } else {
        setCurrentStep("");
      }
    } catch (err: any) {
      if (err.name === "AbortError") {
        toast({ title: "Operator Timeout", description: "The request timed out after 180 seconds. The AI may be overloaded or unreachable.", variant: "destructive" });
      } else {
        toast({ title: "Operator Error", description: err.message, variant: "destructive" });
      }
    } finally {
      setIsLoading(false);
      setCurrentStep("");
    }
  };

  const handleApprove = async (runId: string) => {
    try {
      await operatorAPI.approveRun(runId);
      toast({ title: "Approved", description: "Playbook execution started." });
      setPollingRunId(runId);
      mutateSession();
    } catch (err: any) {
      toast({ title: "Approval Error", description: err.message, variant: "destructive" });
    }
  };

  const sessions = sessionsData?.sessions ?? [];
  const messages = sessionDetail?.messages ?? [];

  // Merge polling status into messages for real-time updates
  const displayMessages: LocalMessage[] = messages.map((m) => {
    if (m.run_id && m.run_id === pollingRunId && runStatus) {
      return {
        ...m,
        status: runStatus.status,
        result: runStatus.result
          ? { ...m.result, ...runStatus.result }
          : m.result,
      };
    }
    return m;
  });

  return (
    <div className="flex flex-col h-full min-h-0 overflow-hidden">
      <PageHeader
        title="AI Operator"
        description="Intelligent system operations through natural language"
      />

      {/* Compact readiness + scope bar */}
      <div className="px-4 py-1.5 flex items-center justify-between border-b bg-muted/20">
        <div className="flex items-center gap-3 text-xs">
          {selectedAssetId ? (
            <>
              <Badge variant="outline" className="text-[10px] bg-primary/5 border-primary/20 h-5 px-1.5">
                <Server className="mr-1 h-3 w-3" />
                Targeted
              </Badge>
              {(() => {
                const asset = assets.find((a) => a.asset_id === selectedAssetId);
                return (
                  <span className="text-muted-foreground">
                    <span className="font-medium text-foreground">{asset?.name || selectedAssetId}</span>
                    {asset?.ip_address && <span> · {asset.ip_address}</span>}
                  </span>
                );
              })()}
            </>
          ) : (
            <>
              <Badge variant="outline" className="text-[10px] bg-muted/50 h-5 px-1.5">
                <Globe className="mr-1 h-3 w-3" />
                Global
              </Badge>
              <span className="text-muted-foreground">No target selected. Operator requires a server scope.</span>
            </>
          )}
        </div>
        {selectedAssetId && assetReadiness && (
          <div className="flex items-center gap-2">
            {!assetReadiness.remediation_enabled ? (
              <Badge variant="outline" className="text-[10px] h-5 px-1.5 text-amber-600 border-amber-300 bg-amber-50">
                <AlertTriangle className="mr-1 h-3 w-3" />
                Remediation disabled
              </Badge>
            ) : (
              <Badge variant="outline" className="text-[10px] h-5 px-1.5 text-green-700 border-green-300 bg-green-50">
                <CheckCircle2 className="mr-1 h-3 w-3" />
                Ready
              </Badge>
            )}
          </div>
        )}
      </div>

      <div className="flex-1 flex gap-4 px-4 pb-4 min-h-0">
        {/* Session Sidebar */}
        <Card className="w-60 hidden md:flex flex-col shrink-0 min-h-0 border-r overflow-hidden">
          <CardHeader className="pb-2 pt-3 px-3">
            <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center justify-between">
              <span>Sessions</span>
              <Button size="sm" variant="ghost" className="h-6 w-6" onClick={handleCreateSession} disabled={!selectedAssetId || !validForExecution || inventoryHosts.length === 0 || (assetReadiness ? !assetReadiness.remediation_enabled : false)}>
                <Plus className="h-3.5 w-3.5" />
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent className="flex-1 overflow-y-auto space-y-0.5 min-h-0 p-1.5">
            {sessions.length === 0 && (
              <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                <Terminal className="h-8 w-8 opacity-40 mb-2" />
                <p className="text-xs text-center max-w-[180px]">No sessions yet. Create one to start operations.</p>
              </div>
            )}
            {sessions.map((s) => (
              <div
                key={s.id}
                className={cn(
                  "group flex items-center justify-between rounded-md border-l-2 px-2.5 py-2 cursor-pointer transition-colors",
                  activeSessionId === s.id
                    ? "bg-primary/10 border-l-primary"
                    : "border-l-transparent hover:bg-muted"
                )}
                onClick={() => setActiveSessionId(s.id)}
              >
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium truncate leading-tight">{s.title}</p>
                  <div className="flex items-center gap-1.5 mt-1">
                    <span className="text-[10px] text-muted-foreground">
                      {s.updated_at && !isNaN(new Date(s.updated_at).getTime()) ? formatDistanceToNow(new Date(s.updated_at), { addSuffix: true }) : "—"}
                    </span>
                  </div>
                </div>
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-5 w-5 opacity-0 group-hover:opacity-100 shrink-0 transition-opacity ml-1"
                  onClick={(e) => {
                    e.stopPropagation();
                    promptDeleteSession(s.id);
                  }}
                >
                  <Trash2 className="h-3 w-3 text-muted-foreground hover:text-destructive" />
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Main Chat */}
        <Card className="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden">
          <CardContent className="flex-1 flex flex-col p-0 min-h-0">
            {/* Target mode bar */}
            <div className="border-b px-4 py-2 flex items-center gap-3 bg-muted/20">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Target</span>
              {selectedAssetId ? (
                <div className="flex items-center gap-2 flex-1">
                  <Badge variant="outline" className="text-xs bg-primary/5 border-primary/20">
                    <Server className="mr-1 h-3 w-3" />
                    Selected server
                  </Badge>
                  {(() => {
                    const asset = assets.find((a) => a.asset_id === selectedAssetId);
                    const ansibleHost = (asset?.ansible_config_json as any)?.ansible_host;
                    const match = inventoryHosts.find(
                      (h) =>
                        h.host === ansibleHost ||
                        h.host === asset?.hostname ||
                        h.host === asset?.ip_address ||
                        h.alias === asset?.asset_id ||
                        h.alias === asset?.hostname
                    );
                    const alias = match?.alias;
                    const host = ansibleHost || asset?.hostname || asset?.ip_address || asset?.asset_id;
                    return (
                      <span className="text-xs">
                        <span className="font-medium">{asset?.name || selectedAssetId}</span>
                        {alias && host && alias !== host && (
                          <span className="text-muted-foreground ml-1">({alias} · {host})</span>
                        )}
                        {alias && (!host || alias === host) && (
                          <span className="text-muted-foreground ml-1">({alias})</span>
                        )}
                        {!alias && host && <span className="text-muted-foreground ml-1">({host})</span>}
                      </span>
                    );
                  })()}
                </div>
              ) : (
                <div className="flex items-center gap-2 flex-1">
                  <Badge variant="outline" className="text-xs bg-muted/50">
                    <Globe className="mr-1 h-3 w-3" />
                    All servers
                  </Badge>
                  <span className="text-xs text-muted-foreground">Select a server to enable execution</span>
                </div>
              )}
            </div>

            {/* Messages */}
            <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-4 min-h-0">
              {!activeSessionId && (
                <div className="flex flex-col items-center justify-center h-full text-muted-foreground space-y-4">
                  <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10">
                    <Bot className="h-7 w-7 text-primary" />
                  </div>
                  <div className="text-center space-y-1">
                    <p className="text-base font-semibold text-foreground">AI Operator</p>
                    <p className="text-sm max-w-sm text-muted-foreground">
                      Create a session and describe what you want to do. The AI will plan, generate
                      an Ansible playbook, and execute it after your approval.
                    </p>
                  </div>
                  <Button
                    onClick={handleCreateSession}
                    disabled={!selectedAssetId || !validForExecution || inventoryHosts.length === 0 || (assetReadiness ? !assetReadiness.remediation_enabled : false)}
                  >
                    <Plus className="h-4 w-4 mr-2" />
                    New Session
                  </Button>
                  {!selectedAssetId && (
                    <div className="flex items-center gap-2 text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
                      <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                      <span className="text-center">Select a server from the global dropdown to create a session.</span>
                    </div>
                  )}
                  {selectedAssetId && (!validForExecution || inventoryHosts.length === 0) && (
                    <p className="text-xs text-red-500 text-center max-w-xs">
                      {inventoryStatusText}. Add hosts to config/ansible_inventory to enable the operator.
                    </p>
                  )}
                  {selectedAssetId && validForExecution && inventoryHosts.length > 0 && assetReadiness && !assetReadiness.remediation_enabled && (
                    <p className="text-xs text-amber-600 text-center max-w-xs">
                      Remediation is not ready for this asset. Configure it in Settings → Ansible.
                    </p>
                  )}
                </div>
              )}

              {activeSessionId && displayMessages.length === 0 && !isLoading && (
                <div className="flex flex-col items-center justify-center h-full text-muted-foreground space-y-3">
                  <Bot className="h-10 w-10 opacity-50" />
                  <p className="text-sm">Describe the operation you want to perform...</p>
                  <div className="text-xs text-muted-foreground space-y-1 text-center">
                    <p>• Check disk usage on the target host</p>
                    <p>• Block IP 10.0.0.5 on the firewall</p>
                    <p>• Restart nginx and verify it&apos;s running</p>
                    <p>• Clean up old log files older than 30 days</p>
                  </div>
                </div>
              )}

              {displayMessages.map((msg) => (
                <div key={msg.id} className="space-y-2">
                  {/* User message */}
                  {msg.role === "user" && (
                    <div className="flex gap-3 justify-end">
                      <div className="max-w-[85%] space-y-1">
                        <div className="rounded-lg px-4 py-2.5 text-sm bg-primary text-primary-foreground">
                          <p className="whitespace-pre-wrap">{msg.content}</p>
                        </div>
                        <MessageTimestamp createdAt={msg.created_at} />
                      </div>
                      <div className="mt-1">
                        <User className="h-5 w-5 text-muted-foreground" />
                      </div>
                    </div>
                  )}

                  {/* Reasoning message */}
                  {msg.role === "reasoning" && (
                    <div className="flex gap-3">
                      <div className="mt-1">
                        <Sparkles className="h-5 w-5 text-primary" />
                      </div>
                      <div className="flex-1 max-w-[85%] space-y-1">
                        <ReasoningCard content={msg.content} />
                        <MessageTimestamp createdAt={msg.created_at} />
                      </div>
                    </div>
                  )}

                  {/* Assistant message */}
                  {msg.role === "assistant" && (
                    <div className="flex gap-3">
                      <div className="mt-1">
                        <Bot className="h-5 w-5 text-primary" />
                      </div>
                      <div className="flex-1 max-w-[90%] space-y-3">
                        <MessageTimestamp createdAt={msg.created_at} />
                        {/* Execution summary */}
                        {msg.execution_summary && (
                          <ExecutionSummaryCard
                            summary={msg.execution_summary}
                            playbookYaml={msg.playbook_yaml}
                            destructiveActions={msg.result?.destructive_actions}
                            estimatedDuration={msg.result?.estimated_duration}
                            riskLevel={msg.risk_level}
                            steps={msg.result?.steps}
                          />
                        )}

                        {/* Approval / Status */}
                        <div className="flex items-center gap-3">
                          {msg.status === "pending_approval" && msg.run_id && (
                            <Button
                              size="sm"
                              onClick={() => handleApprove(msg.run_id!)}
                              className="gap-1.5"
                            >
                              <Play className="h-3.5 w-3.5" />
                              Execute
                            </Button>
                          )}
                          {msg.status === "running" && (
                            <Badge variant="outline" className="gap-1.5 text-xs bg-blue-100 text-blue-800 border-blue-300">
                              <Loader2 className="h-3 w-3 animate-spin" />
                              Running...
                            </Badge>
                          )}
                          {msg.status === "completed" && (
                            <Badge variant="outline" className="gap-1.5 text-xs bg-green-100 text-green-800 border-green-300">
                              <CheckCircle2 className="h-3 w-3" />
                              Completed
                            </Badge>
                          )}
                          {msg.status === "failed" && (
                            <Badge variant="outline" className="gap-1.5 text-xs bg-red-100 text-red-800 border-red-300">
                              <XCircle className="h-3 w-3" />
                              Failed
                            </Badge>
                          )}
                          {msg.risk_level && (
                            <Badge variant="outline" className={cn("text-xs", riskBadgeColor(msg.risk_level))}>
                              {msg.risk_level.toUpperCase()} RISK
                            </Badge>
                          )}
                        </div>

                        {/* Result explanation */}
                        {msg.result?.analysis?.explanation && <ResultCard result={msg.result} />}
                      </div>
                    </div>
                  )}

                  {/* System message */}
                  {msg.role === "system" && (
                    <div className="flex gap-3">
                      <div className="mt-1">
                        <ShieldAlert className="h-5 w-5 text-destructive" />
                      </div>
                      <div className="max-w-[85%] space-y-1">
                        <div className="rounded-lg px-4 py-2.5 text-sm bg-destructive/10 text-destructive">
                          <p className="whitespace-pre-wrap">{msg.content}</p>
                        </div>
                        <MessageTimestamp createdAt={msg.created_at} />
                      </div>
                    </div>
                  )}
                </div>
              ))}

              {isLoading && (
                <div className="flex flex-col gap-2 text-muted-foreground">
                  <div className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span className="text-sm font-medium">AI Operator</span>
                  </div>
                  {currentStep && (
                    <span className="text-xs text-muted-foreground ml-6">{currentStep}</span>
                  )}
                </div>
              )}
            </div>

            {/* Input */}
            <div className="border-t bg-background/50 backdrop-blur p-4">
              <AIChatInput
                value={input}
                onChange={setInput}
                onSubmit={handleSend}
                placeholder={
                  activeSessionId
                    ? "Your infrastructure deserves better observability"
                    : "Create a session first"
                }
                placeholders={activeSessionId ? operatorPlaceholders : undefined}
                disabled={!activeSessionId || isLoading}
                isLoading={isLoading}
              />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Delete Session Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Session</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this session? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => { setDeleteDialogOpen(false); setSessionToDelete(null); }}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteSession}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
