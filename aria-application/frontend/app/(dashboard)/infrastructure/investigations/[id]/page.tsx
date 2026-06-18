"use client";

import { use, useState, useMemo } from "react";
import useSWR from "swr";
import { useRouter, useSearchParams } from "next/navigation";
import { formatAbsoluteDateTime } from "@/lib/time";
import {
  ArrowLeft,
  HardDrive,
  Server,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Play,
  Clock,
  Activity,
  Terminal,
  ThumbsUp,
  ThumbsDown,
  Eye,
  FileCode,
  BarChart3,
  History,
  Gauge,
  Microscope,
  ShieldCheck,
  AlertOctagon,
} from "lucide-react";
import {
  infrastructureAPI,
  type InfrastructureInvestigation,
  type ResourceContext,
} from "@/lib/api";
import { useWSSubscription } from "@/lib/websocket";
import { PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";

import { ResourceGauge, ResourceTypeIcon, ResourceColor } from "@/components/infrastructure/resource-gauge";
import { ProcessTable } from "@/components/infrastructure/process-table";
import { ActionCards } from "@/components/infrastructure/action-cards";
import { PlaybookViewer } from "@/components/infrastructure/playbook-viewer";
// Approval dialogs removed — diagnostic-first workflow uses acknowledge/escalate instead
import { ActivityTimeline } from "@/components/infrastructure/activity-timeline";
import { DiagnosticFindingsCard } from "@/components/infrastructure/diagnostic-findings";
import { DiagnosticOutputCard } from "@/components/infrastructure/diagnostic-output";

export default function InfrastructureInvestigationDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const router = useRouter();
  const searchParams = useSearchParams();
  const [activeTab, setActiveTab] = useState("findings");
  const [actionLoading, setActionLoading] = useState(false);

  const { data: inv, error, isLoading, mutate } = useSWR<InfrastructureInvestigation>(
    id ? `infrastructure-investigation-${id}` : null,
    () => infrastructureAPI.get(id),
    { refreshInterval: 10000 }
  );

  // WebSocket live updates
  useWSSubscription("investigation_updated", (msg) => {
    if ((msg.data as any)?.investigation_id === id) {
      mutate();
    }
  });

  // API-driven timeline
  const { data: timelineData } = useSWR(
    id ? `infrastructure-timeline-${id}` : null,
    () => infrastructureAPI.getTimeline(id),
    { refreshInterval: 30000 }
  );

  const ctx: ResourceContext | undefined = inv?.resource_context || undefined;
  const findings = inv?.findings_json || null;

  // Derive the ACTUAL culprit from findings (accurate) instead of stale ctx.affected_process
  const parsedCulprit = useMemo(() => {
    if (!findings?.detected_cause) return null;
    const match = findings.detected_cause.match(/^(.*?)\s*\(PID\s+(\d+)\)/);
    if (match) {
      return { name: match[1].trim(), pid: match[2] };
    }
    return null;
  }, [findings?.detected_cause]);

  // For disk alerts: extract actual directory consumers from findings evidence
  const diskConsumers = useMemo(() => {
    if (ctx?.resource_type !== "disk" || !findings?.evidence) return [];
    return findings.evidence
      .filter((e: any) => e.source === "du output")
      .map((e: any) => {
        // Parse "path: size" format (handles both "." and "," as decimal separators)
        const finding = e.finding || "";
        const colonIdx = finding.indexOf(":");
        if (colonIdx > 0) {
          return {
            path: finding.slice(0, colonIdx).trim(),
            size: finding.slice(colonIdx + 1).trim(),
          };
        }
        return { path: finding, size: "" };
      })
      .filter((d: any) => d.path);
  }, [ctx?.resource_type, findings?.evidence]);

  const handleAcknowledge = async () => {
    setActionLoading(true);
    try {
      await infrastructureAPI.acknowledge(id);
      mutate();
    } catch (e) {
      console.error("Acknowledge failed", e);
    } finally {
      setActionLoading(false);
    }
  };

  const handleEscalate = async () => {
    setActionLoading(true);
    try {
      await infrastructureAPI.escalate(id);
      mutate();
    } catch (e) {
      console.error("Escalate failed", e);
    } finally {
      setActionLoading(false);
    }
  };

  const handleArchive = async () => {
    setActionLoading(true);
    try {
      await infrastructureAPI.archive(id);
      mutate();
    } catch (e) {
      console.error("Archive failed", e);
    } finally {
      setActionLoading(false);
    }
  };

  const timelineEvents = useMemo(() => {
    if (!timelineData?.events) return [];
    return timelineData.events.map((evt, idx) => ({
      id: `${id}-evt-${idx}`,
      timestamp: evt.timestamp || "",
      type: evt.type as any,
      actor: String(evt.decided_by || "") || undefined,
      detail: String(evt.description || evt.reason || ""),
    }));
  }, [timelineData, id]);

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full" />
      </div>
    );
  }

  if (error || !inv) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4">
        <AlertTriangle className="h-12 w-12 text-destructive" />
        <p className="text-muted-foreground">Failed to load investigation</p>
        <Button variant="outline" onClick={() => router.back()}>
          <ArrowLeft className="h-4 w-4 mr-2" />
          Go Back
        </Button>
      </div>
    );
  }

  const canAcknowledge = inv.status === "findings_ready";
  const canEscalate = inv.status === "findings_ready";
  const canArchive = ["acknowledged", "escalated"].includes(inv.status);

  return (
    <div className="flex flex-col">
      <PageHeader
        title={inv.incident_title}
        backHref="/infrastructure/investigations"
        description={
          <span className="flex items-center gap-2">
            <Server className="h-3.5 w-3.5" />
            {inv.target_host || "unknown"}
            <span className="text-border">|</span>
            <Clock className="h-3.5 w-3.5" />
            {formatAbsoluteDateTime(inv.created_at)}
          </span>
        }
        onRefresh={() => mutate()}
        isLoading={isLoading}
        badge={
          <div className="flex items-center gap-2">
            <Badge variant="outline" className={cn("gap-1.5 font-medium", ResourceColor(ctx?.resource_type))}>
              <ResourceTypeIcon type={ctx?.resource_type} className="h-3.5 w-3.5" />
              {ctx?.resource_type?.toUpperCase() || "UNKNOWN"}
            </Badge>
            <SeverityBadge severity={inv.incident_severity} />
            <StatusBadge status={inv.status} />
          </div>
        }
        actions={
          <div className="flex items-center gap-2">
            {canAcknowledge && (
              <Button variant="default" size="sm" className="gap-2" onClick={handleAcknowledge} disabled={actionLoading}>
                <CheckCircle2 className="h-4 w-4" />
                Acknowledge
              </Button>
            )}
            {canEscalate && (
              <Button variant="outline" size="sm" className="gap-2" onClick={handleEscalate} disabled={actionLoading}>
                <AlertOctagon className="h-4 w-4" />
                Escalate
              </Button>
            )}
            {canArchive && (
              <Button variant="outline" size="sm" className="gap-2" onClick={handleArchive} disabled={actionLoading}>
                <HardDrive className="h-4 w-4" />
                Archive
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={() => router.push("/infrastructure/investigations")}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
          </div>
        }
      />

      <div className="flex-1 space-y-4 p-6">
        {/* Diagnostic status banner */}
        {inv.status === "diagnosing" && (
          <Card className="border-l-4 border-l-blue-500">
            <CardContent className="flex items-center gap-3 py-3">
              <div className="animate-spin h-5 w-5 border-2 border-blue-500 border-t-transparent rounded-full" />
              <div className="flex-1">
                <span className="font-medium text-blue-500">Diagnostic in progress</span>
                <span className="text-muted-foreground ml-2">
                  Collecting evidence from {inv.target_host}...
                </span>
              </div>
            </CardContent>
          </Card>
        )}
        {inv.status === "findings_ready" && (
          <Card className="border-l-4 border-l-emerald-500">
            <CardContent className="flex items-center gap-3 py-3">
              <ShieldCheck className="h-5 w-5 text-emerald-500" />
              <div className="flex-1">
                <span className="font-medium text-emerald-500">Diagnostic complete</span>
                <span className="text-muted-foreground ml-2">
                  Findings are ready for review. Review the recommendations and acknowledge or escalate.
                </span>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Resource Gauge */}
        {ctx && (
          <ResourceGauge
            type={ctx.resource_type}
            value={ctx.current_value}
            threshold={ctx.threshold}
            unit={ctx.unit}
            trend={ctx.historical_trend}
            baselineDeviation={ctx.baseline_deviation}
            severity={inv.incident_severity}
          />
        )}

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <TabsList>
            <TabsTrigger value="findings" className="gap-1.5">
              <Microscope className="h-4 w-4" />
              Findings
            </TabsTrigger>
            <TabsTrigger value="metrics" className="gap-1.5">
              <BarChart3 className="h-4 w-4" />
              Metrics
            </TabsTrigger>
            <TabsTrigger value="output" className="gap-1.5">
              <Terminal className="h-4 w-4" />
              Diagnostic Output
            </TabsTrigger>
            <TabsTrigger value="timeline" className="gap-1.5">
              <History className="h-4 w-4" />
              Timeline
            </TabsTrigger>
          </TabsList>

          {/* Findings */}
          <TabsContent value="findings" className="space-y-4">
            <DiagnosticFindingsCard findings={inv.findings_json ?? null} />

            {ctx && (
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Activity className="h-4 w-4 text-primary" />
                    Resource Details
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <DetailRow label="Host" value={ctx.affected_host || "—"} />
                  {/* Service is irrelevant for disk — show only for CPU/Memory */}
                  {ctx.resource_type !== "disk" && (
                    <DetailRow label="Service" value={parsedCulprit?.name || ctx.affected_service || "—"} />
                  )}
                  <DetailRow label="Resource" value={ctx.resource_type ? ctx.resource_type.charAt(0).toUpperCase() + ctx.resource_type.slice(1) : "—"} />
                  <DetailRow label="Current Value" value={`${ctx.current_value?.toFixed?.(1) ?? "—"} ${ctx.unit || ""}`} mono />
                  <DetailRow label="Threshold" value={`${ctx.threshold?.toFixed?.(1) ?? "—"} ${ctx.unit || ""}`} mono />
                  {ctx.historical_trend && ctx.historical_trend !== "unknown" && (
                    <DetailRow label="Trend" value={ctx.historical_trend.replace("_", " ")} />
                  )}
                  {ctx.baseline_deviation && (
                    <DetailRow label="Baseline Deviation" value={ctx.baseline_deviation} mono />
                  )}
                  {/* Disk consumers (data-aware) */}
                  {ctx.resource_type === "disk" && diskConsumers.length > 0 && (
                    <div className="border-t pt-3">
                      <div className="text-xs text-muted-foreground mb-1.5">Largest Directories</div>
                      <div className="space-y-1.5">
                        {diskConsumers.map((d: any, i: number) => (
                          <div key={i} className="flex items-center justify-between gap-2 text-sm">
                            <div className="flex items-center gap-2 min-w-0">
                              <HardDrive className="h-3.5 w-3.5 text-primary shrink-0" />
                              <span className="font-medium truncate" title={d.path}>{d.path}</span>
                            </div>
                            <span className="text-xs text-muted-foreground font-mono shrink-0">{d.size}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Responsible Process (CPU/Memory only) */}
                  {ctx.resource_type !== "disk" && (parsedCulprit || ctx.affected_process) && (
                    <div className="border-t pt-3">
                      <div className="text-xs text-muted-foreground mb-1.5">Responsible Process</div>
                      <div className="flex items-center gap-2">
                        <Terminal className="h-3.5 w-3.5 text-primary" />
                        <span className="font-medium text-sm">{parsedCulprit?.name || ctx.affected_process?.name}</span>
                        <span className="text-xs text-muted-foreground font-mono">PID {parsedCulprit?.pid || ctx.affected_process?.pid}</span>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Metrics */}
          <TabsContent value="metrics" className="space-y-4">
            {ctx?.metrics_snapshot && (
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <BarChart3 className="h-4 w-4 text-primary" />
                    System Metrics Snapshot
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {[
                      { label: "CPU Usage", value: ctx.metrics_snapshot.cpu_usage_percent, unit: "%" },
                      { label: "Memory", value: ctx.metrics_snapshot.memory_used_percent, unit: "%" },
                      { label: "Load (1m)", value: ctx.metrics_snapshot.load_1, unit: "" },
                      { label: "Load (5m)", value: ctx.metrics_snapshot.load_5, unit: "" },
                      { label: "Load (15m)", value: ctx.metrics_snapshot.load_15, unit: "" },
                      { label: "Processes", value: ctx.metrics_snapshot.proc_total, unit: "" },
                      { label: "TCP Established", value: ctx.metrics_snapshot.tcp_established, unit: "" },
                      { label: "TCP Listen", value: ctx.metrics_snapshot.tcp_listen, unit: "" },
                    ].map((m) => (
                      <div key={m.label} className="rounded-lg border p-3 space-y-1">
                        <div className="text-xs text-muted-foreground">{m.label}</div>
                        <div className="text-lg font-mono font-medium">
                          {typeof m.value === "number" ? m.value.toFixed(m.unit === "%" ? 1 : 2) : "—"}
                          {m.unit}
                        </div>
                      </div>
                    ))}
                  </div>

                  {ctx.metrics_snapshot.disk_devices && ctx.metrics_snapshot.disk_devices.length > 0 && (
                    <div className="border-t pt-4">
                      <div className="text-sm font-medium mb-3">Disk Devices</div>
                      <div className="space-y-2">
                        {ctx.metrics_snapshot.disk_devices.map((disk: any, idx: number) => (
                          <div key={idx} className="flex items-center gap-3 text-sm">
                            <span className="text-muted-foreground w-20">{disk.path || disk.device || "—"}</span>
                            <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                              <div
                                className={cn(
                                  "h-full rounded-full transition-all",
                                  disk.used_percent >= 90 ? "bg-destructive" : disk.used_percent >= 80 ? "bg-warning" : "bg-success"
                                )}
                                style={{ width: `${Math.min(100, disk.used_percent || 0)}%` }}
                              />
                            </div>
                            <span className="font-mono text-xs w-12 text-right">{disk.used_percent?.toFixed?.(1) ?? "—"}%</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Diagnostic Output */}
          <TabsContent value="output" className="space-y-4">
            <DiagnosticOutputCard output={inv.diagnostic_output ?? null} />
            {inv.playbook_yaml && (
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2 text-muted-foreground">
                    <FileCode className="h-4 w-4" />
                    Diagnostic Playbook (for reference)
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <PlaybookViewer yaml={inv.playbook_yaml} />
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Timeline */}
          <TabsContent value="timeline">
            <ActivityTimeline events={timelineEvents} />
          </TabsContent>
        </Tabs>
      </div>

      {/* Dialogs removed — diagnostic-first workflow uses inline acknowledge/escalate buttons */}
    </div>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex justify-between text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className={cn("font-medium", mono && "font-mono")}>{value}</span>
    </div>
  );
}

function MetricBox({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border p-3 space-y-1">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div>{value}</div>
    </div>
  );
}
