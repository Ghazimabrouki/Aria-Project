"use client";

import { useCallback, useState } from "react";
import useSWR from "swr";
import { formatDistanceToNow } from "date-fns";
import {
  Workflow,
  Play,
  Pause,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  XCircle,
  RotateCcw,
  Eye,
  Save,
  Database,
  Server,
} from "lucide-react";
import { pipelineAPI, settingsAPI } from "@/lib/api";
import { useWSSubscription, type WSMessage } from "@/lib/websocket";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  useSettingsSection,
  SettingsField,
} from "@/components/settings-forms";
import { SelectedAssetBanner, GlobalScopeBanner } from "@/components/selected-asset-banner";
import { useSelectedAsset } from "@/lib/asset-context";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

interface PipelineItem {
  name: string;
  status: string;
  processed_count: number;
  error_count: number;
  last_processed: string | null;
}

const SOURCE_LABELS: Record<string, string> = {
  wazuh: "Wazuh",
  falco: "Falco",
  filebeat: "Filebeat",
  suricata: "Suricata",
};

export default function PipelineSettingsPage() {
  const { selectedAssetId } = useSelectedAsset();

  const {
    data: sourcesData,
    isLoading: sourcesLoading,
    error: sourcesError,
    mutate: mutateSources,
  } = useSWR(
    "pipeline-sources",
    () => pipelineAPI.getSources(),
    { refreshInterval: 5000 }
  );

  const {
    data: stats,
    error: statsError,
    mutate: mutateStats,
  } = useSWR(
    ["pipeline-stats", selectedAssetId],
    () => pipelineAPI.getStats(selectedAssetId || undefined),
    { refreshInterval: 10000 }
  );

  const {
    data: cursorStatus,
    mutate: mutateCursors,
  } = useSWR(
    "pipeline-cursor-status",
    () => pipelineAPI.getCursorStatus(),
    { refreshInterval: 10000 }
  );

  const { values: pipelineValues, mutate: mutatePipelineSettings } = useSettingsSection("pipeline");

  const [form, setForm] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [adminSecret, setAdminSecret] = useState("");
  const [askSecret, setAskSecret] = useState(false);
  const [resetSource, setResetSource] = useState<string | null>(null);
  const [resetConfirm, setResetConfirm] = useState("");
  const [resetOpen, setResetOpen] = useState(false);

  const handleWSUpdate = useCallback((message: WSMessage) => {
    mutateSources();
    mutateStats();
  }, [mutateSources, mutateStats]);

  const pipelineList: PipelineItem[] = sourcesData?.sources?.map((source) => ({
      name: source.source,
      status: source.status || "stopped",
      processed_count: source.processed_count || source.documents_tracked || 0,
      error_count: source.error_count || 0,
      last_processed: source.last_run || source.cursor,
    })) || [];

  const pipelineStats = stats || { total_processed: 0, error_rate: 0, avg_processing_time: 0, total_alerts: 0, total_incidents: 0, total_investigations: 0 };

  const runningCount = pipelineList.filter((p) => p.status === "running").length;
  const degradedCount = pipelineList.filter((p) => p.status === "degraded").length;
  const totalErrors = pipelineList.reduce((acc, p) => acc + p.error_count, 0);

  const isLoading = sourcesLoading;
  const hasError = sourcesError || statsError;

  const getField = (key: string) => {
    if (form[key] !== undefined) return form[key];
    const v = pipelineValues.find((x) => x.key === key);
    if (!v) return "";
    return String(v.value ?? "");
  };

  const setField = (key: string, val: string) => setForm((prev) => ({ ...prev, [key]: val }));

  const hasFormChanges = Object.keys(form).length > 0;

  const buildChanges = () => {
    const changes: Record<string, any> = {};
    ["wazuh_poll_interval_seconds", "falco_poll_interval_seconds", "filebeat_poll_interval_seconds", "suricata_poll_interval_seconds"].forEach((k) => {
      if (form[k] !== undefined) {
        const val = parseInt(form[k], 10);
        if (!isNaN(val) && val >= 5) {
          changes[k] = val;
        }
      }
    });
    if (form.opensoar_poll_interval !== undefined) {
      const val = parseInt(form.opensoar_poll_interval, 10);
      if (!isNaN(val) && val >= 5) changes.opensoar_poll_interval = val;
    }
    if (form.opensoar_batch_size !== undefined) {
      const val = parseInt(form.opensoar_batch_size, 10);
      if (!isNaN(val) && val >= 1) changes.opensoar_batch_size = val;
    }
    return changes;
  };

  const doSave = async () => {
    const changes = buildChanges();
    if (Object.keys(changes).length === 0) {
      toast.info("No changes to save.");
      return;
    }
    setSaving(true);
    try {
      const res = await settingsAPI.update({ changes, reload: true }, adminSecret);
      if (res.errors?.length) {
        toast.error(res.errors.join("; "));
      } else {
        toast.success("Pipeline settings saved.");
        setForm({});
        await mutatePipelineSettings();
      }
    } catch (e: any) {
      const msg = e?.response?.data?.detail || e.message || "Save failed";
      toast.error(msg);
    } finally {
      setSaving(false);
    }
  };

  const handleSave = () => {
    if (!adminSecret) {
      setAskSecret(true);
      return;
    }
    doSave();
  };

  const openReset = (source: string) => {
    setResetSource(source);
    setResetConfirm("");
    setResetOpen(true);
  };

  const handleReset = async () => {
    if (!resetSource) return;
    if (resetConfirm.trim() !== "RESET CURSOR") {
      toast.error("Type RESET CURSOR to confirm.");
      return;
    }
    if (!adminSecret) {
      setResetOpen(false);
      setAskSecret(true);
      return;
    }
    try {
      const res = await pipelineAPI.resetCursor(resetSource, resetConfirm.trim(), adminSecret);
      toast.success(res.message);
      setResetOpen(false);
      setResetConfirm("");
      await mutateCursors();
    } catch (e: any) {
      const msg = e?.response?.data?.detail || e.message || "Reset failed";
      toast.error(msg);
    }
  };

  const dedupMode = cursorStatus?.dedup_mode || "unknown";

  return (
    <div className="flex flex-col">
      <PageHeader
        title="Pipeline"
        description="Alert ingestion and processing status"
        onRefresh={() => {
          mutateSources();
          mutateStats();
          mutateCursors();
          mutatePipelineSettings();
        }}
        isLoading={isLoading}
      />

      <div className="flex-1 space-y-6 p-6">
        <SelectedAssetBanner />
        <GlobalScopeBanner />

        {/* Stats Cards */}
        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Total Processed</p>
                  <p className="text-3xl font-bold">
                    {pipelineStats.total_processed.toLocaleString()}
                  </p>
                </div>
                <Workflow className="h-10 w-10 text-primary/30" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Active Pipelines</p>
                  <p className="text-3xl font-bold text-success">{runningCount}</p>
                </div>
                <Play className="h-10 w-10 text-success/30" />
              </div>
            </CardContent>
          </Card>
          <Card className={cn(pipelineStats.error_rate > 0.05 && "border-warning/50")}>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Error Rate</p>
                  <p className={cn(
                    "text-3xl font-bold",
                    pipelineStats.error_rate > 0.05 && "text-warning",
                    pipelineStats.error_rate > 0.1 && "text-destructive"
                  )}>
                    {(pipelineStats.error_rate * 100).toFixed(2)}%
                  </p>
                </div>
                <AlertTriangle className={cn(
                  "h-10 w-10",
                  pipelineStats.error_rate > 0.05 ? "text-warning/30" : "text-muted-foreground/30"
                )} />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Avg Processing</p>
                  <p className="text-3xl font-bold">{pipelineStats.avg_processing_time}ms</p>
                </div>
                <ArrowRight className="h-10 w-10 text-muted-foreground/30" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Poll Intervals */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base font-medium">Poll Intervals</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              {["wazuh", "falco", "filebeat", "suricata"].map((source) => (
                <div key={source} className="space-y-2">
                  <Label className="capitalize">{SOURCE_LABELS[source]} (seconds)</Label>
                  <Input
                    type="number"
                    min={5}
                    max={3600}
                    value={getField(`${source}_poll_interval_seconds`)}
                    onChange={(e) => setField(`${source}_poll_interval_seconds`, e.target.value)}
                    placeholder="10"
                  />
                  <p className="text-xs text-muted-foreground">Recommended: 10–300s</p>
                </div>
              ))}
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <Button onClick={handleSave} disabled={saving || !hasFormChanges}>
                <Save className="h-4 w-4 mr-1" />
                {saving ? "Saving..." : "Save Intervals"}
              </Button>
              {hasFormChanges && (
                <Button variant="ghost" onClick={() => setForm({})}>Discard</Button>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Cursor Status + Dedup */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-base font-medium">Cursor & Deduplication Status</CardTitle>
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-muted-foreground" />
                <Badge variant="outline">{dedupMode === "redis" ? "Redis Dedup" : dedupMode === "file" ? "File Dedup" : "Unknown"}</Badge>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {cursorStatus ? (
              <div className="space-y-4">
                {cursorStatus.sources?.map((source: string) => {
                  const cs = cursorStatus.cursors?.[source];
                  const hasCursor = cs?.redis_present || cs?.file_present;
                  const cursorValue = cs?.redis_value || cs?.file_value;
                  return (
                    <div key={source} className="rounded-lg border p-4 space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-medium capitalize">{SOURCE_LABELS[source] || source}</span>
                          {hasCursor ? (
                            <Badge variant="secondary" className="text-xs">Cursor set</Badge>
                          ) : (
                            <Badge variant="outline" className="text-xs text-muted-foreground">No cursor</Badge>
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          {hasCursor && (
                            <div className="text-right mr-4">
                              <p className="text-xs text-muted-foreground">Last processed</p>
                              <p className="text-xs font-mono">
                                {cursorValue
                                  ? formatDistanceToNow(new Date(cursorValue), { addSuffix: true })
                                  : "N/A"}
                              </p>
                            </div>
                          )}
                          <Button size="sm" variant="outline" onClick={() => openReset(source)}>
                            <RotateCcw className="h-3.5 w-3.5 mr-1" />
                            Reset Cursor
                          </Button>
                        </div>
                      </div>
                      {hasCursor && cursorValue && (
                        <div className="text-xs font-mono text-muted-foreground bg-muted rounded px-2 py-1 truncate">
                          {cursorValue}
                        </div>
                      )}
                      <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                        {cs?.redis_present && <Badge variant="outline" className="text-xs">Redis</Badge>}
                        {cs?.file_present && <Badge variant="outline" className="text-xs">File</Badge>}
                        <span className="text-xs">{cursorStatus.cursor_dir}/{source}.cursor</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="space-y-2"><div className="h-3 w-full bg-muted rounded" /><div className="h-3 w-2/3 bg-muted rounded" /></div>
            )}
          </CardContent>
        </Card>

        {/* Pipeline Flow */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base font-medium">Pipeline Flow</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between gap-4 overflow-x-auto pb-4">
              <div className="flex min-w-fit flex-col gap-2">
                <p className="text-xs font-medium text-muted-foreground">Sources</p>
                <div className="space-y-2">
                  {pipelineList.length > 0 ? (
                    pipelineList.map((source) => (
                      <div
                        key={source.name}
                        className="flex items-center gap-2 rounded-lg border bg-card px-3 py-2"
                      >
                        <div className="h-2 w-2 animate-pulse rounded-full bg-primary" />
                        <span className="text-sm font-medium capitalize">{source.name}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-sm text-muted-foreground">No sources connected</div>
                  )}
                </div>
              </div>
              <ArrowRight className="h-6 w-6 shrink-0 text-muted-foreground" />
              <div className="flex min-w-fit flex-col gap-2">
                <p className="text-xs font-medium text-muted-foreground">Processing</p>
                <div className="rounded-lg border bg-primary/5 p-4">
                  <div className="flex items-center gap-2">
                    <Workflow className="h-5 w-5 text-primary" />
                    <span className="font-medium">Pipeline Workers</span>
                  </div>
                  <p className="mt-2 text-sm text-muted-foreground">
                    Parsing, normalization, enrichment
                  </p>
                </div>
              </div>
              <ArrowRight className="h-6 w-6 shrink-0 text-muted-foreground" />
              <div className="flex min-w-fit flex-col gap-2">
                <p className="text-xs font-medium text-muted-foreground">Correlation</p>
                <div className="rounded-lg border bg-success/5 p-4">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-5 w-5 text-success" />
                    <span className="font-medium">Alert Correlator</span>
                  </div>
                  <p className="mt-2 text-sm text-muted-foreground">
                    Pattern matching, incident creation
                  </p>
                </div>
              </div>
              <ArrowRight className="h-6 w-6 shrink-0 text-muted-foreground" />
              <div className="flex min-w-fit flex-col gap-2">
                <p className="text-xs font-medium text-muted-foreground">Output</p>
                <div className="space-y-2">
                  {[
                    { label: "Alerts", count: pipelineStats.total_alerts ?? 0 },
                    { label: "Incidents", count: pipelineStats.total_incidents ?? 0 },
                    { label: "Investigations", count: pipelineStats.total_investigations ?? 0 },
                  ].map((output) => (
                    <div
                      key={output.label}
                      className="flex items-center justify-between gap-4 rounded-lg border bg-success/5 px-3 py-2"
                    >
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="h-4 w-4 text-success" />
                        <span className="text-sm font-medium">{output.label}</span>
                      </div>
                      <span className="text-xs font-mono text-muted-foreground">
                        {output.count.toLocaleString()}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Pipeline Status */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base font-medium">Pipeline Status</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="space-y-3"><div className="h-4 w-32 bg-muted rounded" /><div className="h-3 w-full bg-muted rounded" /><div className="h-3 w-4/5 bg-muted rounded" /></div>
            ) : hasError ? (
              <div className="text-sm text-destructive">
                Failed to load pipeline data. {hasError instanceof Error ? hasError.message : ""}
              </div>
            ) : pipelineList.length === 0 ? (
              <div className="text-sm text-muted-foreground">No pipelines available.</div>
            ) : (
              <div className="space-y-4">
                {pipelineList.map((pipeline) => {
                  const errorRate = pipeline.processed_count > 0
                    ? (pipeline.error_count / pipeline.processed_count) * 100
                    : 0;
                  const isHighError = errorRate > 1;

                  return (
                    <div
                      key={pipeline.name}
                      className={cn(
                        "rounded-lg border p-4",
                        pipeline.status === "error" && "border-destructive/50 bg-destructive/5",
                        pipeline.status === "stopped" && "border-muted bg-muted/50",
                        isHighError && pipeline.status === "running" && "border-warning/50"
                      )}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div
                            className={cn(
                              "flex h-10 w-10 items-center justify-center rounded-lg",
                              pipeline.status === "running" && "bg-success/10 text-success",
                              pipeline.status === "stopped" && "bg-muted text-muted-foreground",
                              pipeline.status === "error" && "bg-destructive/10 text-destructive"
                            )}
                          >
                            {pipeline.status === "running" ? (
                              <Play className="h-5 w-5" />
                            ) : pipeline.status === "stopped" ? (
                              <Pause className="h-5 w-5" />
                            ) : (
                              <XCircle className="h-5 w-5" />
                            )}
                          </div>
                          <div>
                            <p className="font-medium">{pipeline.name}</p>
                            <p className="text-sm text-muted-foreground">
                              Last processed{" "}
                              {pipeline.last_processed
                                ? formatDistanceToNow(new Date(pipeline.last_processed), {
                                    addSuffix: true,
                                  })
                                : "never"}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center gap-8">
                          <div className="text-right">
                            <p className="text-xs text-muted-foreground">Processed</p>
                            <p className="font-mono text-sm font-medium">
                              {pipeline.processed_count.toLocaleString()}
                            </p>
                          </div>
                          <div className="text-right">
                            <p className="text-xs text-muted-foreground">Errors</p>
                            <p
                              className={cn(
                                "font-mono text-sm font-medium",
                                isHighError && "text-warning"
                              )}
                            >
                              {pipeline.error_count} ({errorRate.toFixed(2)}%)
                            </p>
                          </div>
                          <StatusBadge status={pipeline.status} />
                        </div>
                      </div>
                      <div className="mt-4">
                        <Progress
                          value={Math.min(
                            pipelineStats.total_processed > 0
                              ? (pipeline.processed_count / pipelineStats.total_processed) * 100 * pipelineList.length
                              : 0,
                            100
                          )}
                          className="h-1.5"
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Reset Cursor Modal */}
      <Dialog open={resetOpen} onOpenChange={setResetOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="text-red-500">Reset Cursor</DialogTitle>
            <DialogDescription>
              Reset the cursor for {resetSource ? SOURCE_LABELS[resetSource] || resetSource : ""}. The next poll will re-process alerts from the lookback window.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label>Type exactly: RESET CURSOR</Label>
            <Input value={resetConfirm} onChange={(e) => setResetConfirm(e.target.value)} placeholder="RESET CURSOR" />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setResetOpen(false)}>Cancel</Button>
            <Button variant="destructive" onClick={handleReset} disabled={resetConfirm.trim() !== "RESET CURSOR"}>
              Reset
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Admin Secret Modal */}
      <Dialog open={askSecret} onOpenChange={setAskSecret}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Admin Secret Required</DialogTitle>
          </DialogHeader>
          <div className="space-y-1.5">
            <label className="text-sm font-medium">X-ARIA-Admin-Secret</label>
            <Input type="password" value={adminSecret} onChange={(e) => setAdminSecret(e.target.value)} placeholder="Enter admin secret..." />
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setAskSecret(false)}>Cancel</Button>
            <Button onClick={() => { setAskSecret(false); if (resetOpen) handleReset(); else doSave(); }} disabled={!adminSecret.trim()}>Continue</Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
