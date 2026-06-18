"use client";
import { ListPageSkeleton } from "@/components/page-skeletons";

import { useState, useCallback, useEffect, useMemo, Suspense } from "react";
import useSWR, { mutate as swrMutate } from "swr";
import { useRouter, useSearchParams } from "next/navigation";
import { format } from "date-fns";
import { formatAbsoluteDateTime, getEventTimestamp } from "@/lib/time";
import { TimeFilter, timePresetToRange, type TimePreset } from "@/components/time-filter";
import {
  ExternalLink,
  X,
  Globe,
  Server,
  Tag,
  AlertTriangle,
  Copy,
  ChevronRight,
  Search,
  FileText,
  Shield,
  Plus,
} from "lucide-react";
import {
  alertsAPI,
  whitelistAPI,
  incidentsAPI,
  type Alert,
  type AlertListResponse,
  type AlertDetailResponse,
} from "@/lib/api";
import { useWSSubscription, type WSMessage } from "@/lib/websocket";
import { useSelectedAsset } from "@/lib/asset-context";
import { PageHeader } from "@/components/page-header";
import { DataTable } from "@/components/data-table";
import { ErrorState } from "@/components/error-state";
import { AlertIocPanel } from "@/components/alert-ioc-panel";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { WhitelistBadge } from "@/components/whitelist-badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

const sourceOptions = [
  { value: "all", label: "All Sources" },
  { value: "wazuh", label: "Wazuh" },
  { value: "suricata", label: "Suricata" },
  { value: "filebeat", label: "Filebeat" },
];

const severityOptions = [
  { value: "all", label: "All Severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const statusOptions = [
  { value: "all", label: "All Statuses" },
  { value: "active", label: "Active" },
  { value: "processed", label: "Processed" },
  { value: "archived", label: "Archived" },
];

function AlertsPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { selectedAssetId } = useSelectedAsset();
  const [offset, setOffset] = useState(0);
  const [source, setSource] = useState(searchParams.get("source") || "all");
  const [severity, setSeverity] = useState(searchParams.get("severity") || "all");
  const [status, setStatus] = useState(searchParams.get("status") || "all");
  const [whitelisted, setWhitelisted] = useState(searchParams.get("whitelisted") || "all");
  const [mitreTechnique, setMitreTechnique] = useState(searchParams.get("mitre_technique") || "");
  const [tactic, setTactic] = useState(searchParams.get("tactic") || "");
  const [timePreset, setTimePreset] = useState<TimePreset>((searchParams.get("time_preset") as TimePreset) || "all");
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(searchParams.get("id") || null);
  const [addingToWhitelist, setAddingToWhitelist] = useState(false);
  const [selectedAlertIds, setSelectedAlertIds] = useState<Set<string>>(new Set());
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [createLoading, setCreateLoading] = useState(false);
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentDescription, setIncidentDescription] = useState("");
  const [incidentSeverity, setIncidentSeverity] = useState<"critical" | "high" | "medium" | "low">("high");
  const [incidentTags, setIncidentTags] = useState("manual");
  const { toast } = useToast();

  const updateSelectedAlert = (id: string | null) => {
    setSelectedAlertId(id);
    const params = new URLSearchParams(searchParams.toString());
    if (id) {
      params.set("id", id);
    } else {
      params.delete("id");
    }
    router.replace(`?${params.toString()}`, { scroll: false });
  };
  const limit = 20;

  const timeRange = useMemo(() => timePresetToRange(timePreset), [timePreset]);

  const { data, error, isLoading, mutate } = useSWR<AlertListResponse>(
    ["alerts", offset, source, severity, status, whitelisted, mitreTechnique, tactic, timePreset, selectedAssetId],
    () =>
      alertsAPI.list({
        limit,
        offset,
        source: source !== "all" ? source : undefined,
        severity: severity !== "all" ? severity : undefined,
        status: status !== "all" ? status : undefined,
        whitelisted: whitelisted !== "all" ? whitelisted === "true" : undefined,
        mitre_technique: mitreTechnique || undefined,
        tactic: tactic || undefined,
        asset_id: selectedAssetId || undefined,
        ...timeRange,
      })
  );

  // Fetch full alert details when one is selected
  const { data: alertDetail, error: detailError, isLoading: detailLoading } = useSWR<AlertDetailResponse>(
    selectedAlertId ? ["alert-detail", selectedAlertId] : null,
    () => alertsAPI.get(selectedAlertId!)
  );

  // Sync selected alert with URL query param for direct links from search/incidents
  useEffect(() => {
    const idFromUrl = searchParams.get("id");
    setSelectedAlertId(idFromUrl);
  }, [searchParams]);

  const handleWSUpdate = useCallback(
    (message: WSMessage) => {
      mutate();
    },
    [mutate]
  );

  // Subscribe to investigation updates as a proxy for alert-related activity
  useWSSubscription("investigation_updated", handleWSUpdate);

  const alerts = data?.alerts || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  const handlePageChange = (page: number) => {
    setOffset((page - 1) * limit);
  };

  const selectedAlerts = alerts.filter((a) => selectedAlertIds.has(a.id));
  const selectedSourceIps = Array.from(new Set(selectedAlerts.map((a) => a.source_ip).filter(Boolean) as string[]));
  const selectedHostnames = Array.from(new Set(selectedAlerts.map((a) => a.hostname).filter(Boolean)));

  const columns = [
    {
      key: "select",
      header: (
        <div onClick={(e) => e.stopPropagation()}>
          <Checkbox
            checked={alerts.length > 0 && alerts.every((a) => selectedAlertIds.has(a.id))}
            onCheckedChange={(checked) => {
              setSelectedAlertIds((prev) => {
                const next = new Set(prev);
                alerts.forEach((a) => {
                  if (checked) next.add(a.id);
                  else next.delete(a.id);
                });
                return next;
              });
            }}
            aria-label="Select all alerts on this page"
          />
        </div>
      ),
      cell: (alert: Alert) => (
        <div onClick={(e) => e.stopPropagation()}>
          <Checkbox
            checked={selectedAlertIds.has(alert.id)}
            onCheckedChange={(checked) => {
              setSelectedAlertIds((prev) => {
                const next = new Set(prev);
                if (checked) next.add(alert.id);
                else next.delete(alert.id);
                return next;
              });
            }}
            aria-label={`Select alert ${alert.title}`}
          />
        </div>
      ),
      className: "w-10",
    },
    {
      key: "severity",
      header: "Severity",
      cell: (alert: Alert) => <SeverityBadge severity={alert.severity} />,
      className: "w-28",
    },
    {
      key: "title",
      header: "Alert",
      cell: (alert: Alert) => (
        <div className="max-w-md">
          <div className="flex items-center gap-2">
            <p className="truncate font-medium">{alert.title}</p>
            {alert.whitelisted && <WhitelistBadge whitelisted={alert.whitelisted} />}
          </div>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-xs text-muted-foreground font-mono">
              {alert.source_ip}
            </span>
            <ChevronRight className="h-3 w-3 text-muted-foreground" />
            <span className="text-xs text-muted-foreground">{alert.hostname}</span>
          </div>
        </div>
      ),
    },
    {
      key: "source",
      header: "Source",
      cell: (alert: Alert) => (
        <Badge variant="outline" className="capitalize">
          {alert.source}
        </Badge>
      ),
      className: "w-28",
    },
    {
      key: "status",
      header: "Status",
      cell: (alert: Alert) => <StatusBadge status={alert.status} />,
      className: "w-32",
    },
    {
      key: "timestamp",
      header: "Time",
      cell: (alert: Alert) => {
        const ts = getEventTimestamp(alert, "alert");
        return (
          <span className="text-sm text-muted-foreground">
            {formatAbsoluteDateTime(ts)}
          </span>
        );
      },
      className: "w-32",
    },
  ];

  const clearFilters = () => {
    setSource("all");
    setSeverity("all");
    setStatus("all");
    setWhitelisted("all");
    setMitreTechnique("");
    setTactic("");
    setTimePreset("all");
    setOffset(0);
    // Clear MITRE drill-down params from URL
    const params = new URLSearchParams(searchParams.toString());
    params.delete("mitre_technique");
    params.delete("tactic");
    router.replace(`?${params.toString()}`, { scroll: false });
  };

  const hasFilters = source !== "all" || severity !== "all" || status !== "all" || whitelisted !== "all" || !!mitreTechnique || !!tactic || timePreset !== "all";

  const selectedAlert = alertDetail?.data;
  const relationships = alertDetail?.relationships;

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="flex flex-col">
      <PageHeader
        icon={AlertTriangle}
        title="Alerts"
        onRefresh={() => mutate()}
        isLoading={isLoading}
        actions={
          <div className="flex items-center gap-2">
            <Select
              value={source}
              onValueChange={(v) => {
                setSource(v);
                setOffset(0);
              }}
            >
              <SelectTrigger className="w-36 max-sm:w-full">
                <SelectValue placeholder="Source" />
              </SelectTrigger>
              <SelectContent>
                {sourceOptions.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={severity}
              onValueChange={(v) => {
                setSeverity(v);
                setOffset(0);
              }}
            >
              <SelectTrigger className="w-36 max-sm:w-full">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                {severityOptions.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={status}
              onValueChange={(v) => {
                setStatus(v);
                setOffset(0);
              }}
            >
              <SelectTrigger className="w-36 max-sm:w-full">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                {statusOptions.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={whitelisted}
              onValueChange={(v) => {
                setWhitelisted(v);
                setOffset(0);
              }}
            >
              <SelectTrigger className="w-40 max-sm:w-full">
                <SelectValue placeholder="Whitelist" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="true">Whitelisted</SelectItem>
                <SelectItem value="false">Not Whitelisted</SelectItem>
              </SelectContent>
            </Select>
            <Input
              placeholder="MITRE Technique"
              aria-label="Filter by MITRE technique"
              className="w-40 max-sm:w-full"
              value={mitreTechnique}
              onChange={(e) => {
                setMitreTechnique(e.target.value);
                setOffset(0);
              }}
            />
            <Input
              placeholder="MITRE Tactic"
              aria-label="Filter by MITRE tactic"
              className="w-40 max-sm:w-full"
              value={tactic}
              onChange={(e) => {
                setTactic(e.target.value);
                setOffset(0);
              }}
            />
            <TimeFilter
              value={timePreset}
              onChange={(v) => {
                setTimePreset(v);
                setOffset(0);
              }}
            />
            {hasFilters && (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                <X className="mr-1 h-4 w-4" />
                Clear
              </Button>
            )}
          </div>
        }
      />

      <div className="flex-1 p-6">
        {selectedAlertIds.size > 0 && (
          <div className="mb-4 flex items-center justify-between rounded-lg border bg-card p-3">
            <div className="flex items-center gap-3">
              <span className="text-sm font-medium">
                {selectedAlertIds.size} alert{selectedAlertIds.size > 1 ? "s" : ""} selected
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSelectedAlertIds(new Set())}
              >
                <X className="mr-1 h-3 w-3" />
                Clear
              </Button>
            </div>
            <Button
              size="sm"
              onClick={() => {
                // Auto-suggest title and description from selected alerts
                const sources = Array.from(new Set(selectedAlerts.map((a) => a.source).filter(Boolean)));
                const sourceText = sources.length > 0 ? sources.map((s) => s.charAt(0).toUpperCase() + s.slice(1)).join("/") : "Mixed";
                const suggestedTitle = `Incident: ${selectedAlerts.length} ${sourceText} alert${selectedAlerts.length > 1 ? "s" : ""}`;
                const suggestedDescription = selectedAlerts.map((a) => `• ${a.title}${a.source_ip ? ` (IP: ${a.source_ip})` : ""}`).join("\n");
                setIncidentTitle(suggestedTitle);
                setIncidentDescription(suggestedDescription);
                setIncidentSeverity("high");
                setIncidentTags("manual");
                setCreateDialogOpen(true);
              }}
            >
              <Plus className="mr-1 h-4 w-4" />
              Create Incident
            </Button>
          </div>
        )}
        {error ? (
          <ErrorState
            title="Failed to load alerts"
            error={error}
            onRetry={() => mutate()}
          />
        ) : (
          <DataTable
            columns={columns}
            data={alerts}
            page={currentPage}
            totalPages={totalPages}
            totalItems={total}
            onPageChange={handlePageChange}
            onRowClick={(alert) => alert.id && updateSelectedAlert(alert.id)}
            isLoading={isLoading}
            emptyMessage="No alerts found"
          />
        )}
      </div>

      {/* Create Incident Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Incident from Alerts</DialogTitle>
            <DialogDescription>
              Create a new incident from {selectedAlertIds.size} selected alert{selectedAlertIds.size > 1 ? "s" : ""}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="title">Title *</Label>
              <Input
                id="title"
                placeholder="Incident title..."
                value={incidentTitle}
                onChange={(e) => setIncidentTitle(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">Description *</Label>
              <Textarea
                id="description"
                placeholder="Describe the incident..."
                value={incidentDescription}
                onChange={(e) => setIncidentDescription(e.target.value)}
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="severity">Severity</Label>
              <Select
                value={incidentSeverity}
                onValueChange={(v) => setIncidentSeverity(v as "critical" | "high" | "medium" | "low")}
              >
                <SelectTrigger id="severity">
                  <SelectValue placeholder="Select severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {selectedSourceIps.length > 0 && (
              <div className="space-y-2">
                <Label>Source IPs</Label>
                <div className="flex flex-wrap gap-1">
                  {selectedSourceIps.map((ip) => (
                    <Badge key={ip} variant="secondary" className="text-xs">
                      {ip}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
            {selectedHostnames.length > 0 && (
              <div className="space-y-2">
                <Label>Hostnames</Label>
                <div className="flex flex-wrap gap-1">
                  {selectedHostnames.map((h) => (
                    <Badge key={h} variant="secondary" className="text-xs">
                      {h}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="tags">Tags</Label>
              <Input
                id="tags"
                placeholder="Comma-separated tags..."
                value={incidentTags}
                onChange={(e) => setIncidentTags(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={createLoading || !incidentTitle.trim() || !incidentDescription.trim()}
              onClick={async () => {
                setCreateLoading(true);
                try {
                  const tags = incidentTags
                    .split(",")
                    .map((t) => t.trim())
                    .filter(Boolean);
                  const incident = await incidentsAPI.createManual({
                    title: incidentTitle.trim(),
                    description: incidentDescription.trim(),
                    severity: incidentSeverity,
                    alert_ids: Array.from(selectedAlertIds),
                    source_ips: selectedSourceIps,
                    hostnames: selectedHostnames,
                    tags: tags.length > 0 ? tags : ["manual"],
                  });
                  toast({ title: "Incident created", description: incident.data.title });
                  setSelectedAlertIds(new Set());
                  setCreateDialogOpen(false);
                  router.push("/incidents");
                } catch (e: any) {
                  toast({
                    title: "Failed to create incident",
                    description: e?.message || "Something went wrong",
                    variant: "destructive",
                  });
                } finally {
                  setCreateLoading(false);
                }
              }}
            >
              {createLoading ? "Creating..." : "Create Incident"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Alert Detail Sheet */}
      <Sheet open={!!selectedAlertId} onOpenChange={() => updateSelectedAlert(null)}>
        <SheetContent className="w-full sm:max-w-[600px] overflow-y-auto">
          <SheetTitle className="sr-only">Alert Details</SheetTitle>
          {detailLoading ? (
            <div className="flex h-full items-center justify-center">
              <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            </div>
          ) : detailError ? (
            <div className="flex h-full flex-col items-center justify-center p-6">
              <ErrorState
                title="Failed to load alert details"
                error={detailError}
                onRetry={() => swrMutate(["alert-detail", selectedAlertId])}
                bordered={false}
              />
              <Button variant="outline" className="mt-4" onClick={() => updateSelectedAlert(null)}>
                Close
              </Button>
            </div>
          ) : selectedAlert ? (
            <>
              <SheetHeader>
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={selectedAlert.severity} />
                  <StatusBadge status={selectedAlert.status} />
                </div>
                <SheetTitle className="text-left">{selectedAlert.title}</SheetTitle>
                <SheetDescription className="text-left">
                  {(() => {
                    const d = selectedAlert.created_at ? new Date(selectedAlert.created_at) : null;
                    return d && !isNaN(d.getTime()) ? format(d, "PPpp") : "—";
                  })()}
                </SheetDescription>
              </SheetHeader>

              <Tabs defaultValue="details" className="mt-6">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="details">Details</TabsTrigger>
                  <TabsTrigger value="iocs">IOCs</TabsTrigger>
                  <TabsTrigger value="related">Related</TabsTrigger>
                </TabsList>

                <TabsContent value="details" className="space-y-4 mt-4">
                  {/* Description */}
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium">Description</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-sm text-muted-foreground">
                        {selectedAlert.description || "No description available"}
                      </p>
                    </CardContent>
                  </Card>

                  {/* Network Info */}
                  <Card>
                    <CardHeader className="pb-2">
                      <div className="flex items-center gap-2">
                        <Globe className="h-4 w-4 text-muted-foreground" />
                        <CardTitle className="text-sm font-medium">Network Information</CardTitle>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Source IP</span>
                        <div className="flex items-center gap-2">
                          <code className="bg-muted px-2 py-1 rounded text-sm font-mono">
                            {selectedAlert.source_ip || "—"}
                          </code>
                          {selectedAlert.source_ip && (
                            <>
                              {selectedAlert.whitelisted && (
                                <Shield className="h-3.5 w-3.5 text-emerald-500" />
                              )}
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-6 w-6"
                                onClick={() => copyToClipboard(selectedAlert.source_ip!)}
                              >
                                <Copy className="h-3 w-3" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-6 w-6"
                                onClick={() => router.push(`/search?q=${selectedAlert.source_ip}`)}
                              >
                                <ExternalLink className="h-3 w-3" />
                              </Button>
                            </>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Destination IP</span>
                        <div className="flex items-center gap-2">
                          <code className="bg-muted px-2 py-1 rounded text-sm font-mono">
                            {selectedAlert.dest_ip || "—"}
                          </code>
                          {selectedAlert.dest_ip && (
                            <>
                              {selectedAlert.whitelisted && (
                                <Shield className="h-3.5 w-3.5 text-emerald-500" />
                              )}
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-6 w-6"
                                onClick={() => copyToClipboard(selectedAlert.dest_ip!)}
                              >
                                <Copy className="h-3 w-3" />
                              </Button>
                            </>
                          )}
                        </div>
                      </div>
                      {selectedAlert.source_ip && !selectedAlert.whitelisted && (
                        <div className="pt-2 border-t">
                          <Button
                            variant="outline"
                            size="sm"
                            className="w-full text-xs"
                            disabled={addingToWhitelist}
                            onClick={async () => {
                              setAddingToWhitelist(true);
                              try {
                                await whitelistAPI.create({
                                  type: "ip",
                                  value: selectedAlert.source_ip!,
                                  label: "trusted",
                                });
                                // Refresh alert detail to pick up whitelisted flag
                                if (selectedAlertId) {
                                  swrMutate(
                                    ["alert-detail", selectedAlertId],
                                    (prev: AlertDetailResponse | undefined) => {
                                      if (!prev?.data) return prev;
                                      return { ...prev, data: { ...prev.data, whitelisted: true } };
                                    },
                                    false
                                  );
                                }
                                mutate();
                              } catch (e) {
                                console.error("Failed to add to whitelist:", e);
                              } finally {
                                setAddingToWhitelist(false);
                              }
                            }}
                          >
                            <Shield className="mr-2 h-3 w-3" />
                            {addingToWhitelist ? "Adding..." : "Add Source IP to Whitelist"}
                          </Button>
                        </div>
                      )}
                    </CardContent>
                  </Card>

                  {/* Host Info */}
                  <Card>
                    <CardHeader className="pb-2">
                      <div className="flex items-center gap-2">
                        <Server className="h-4 w-4 text-muted-foreground" />
                        <CardTitle className="text-sm font-medium">Host Information</CardTitle>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Hostname</span>
                        <Badge variant="secondary">{selectedAlert.hostname || "—"}</Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Source</span>
                        <Badge variant="outline" className="capitalize">
                          {selectedAlert.source}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Rule</span>
                        <span className="text-sm font-medium">{selectedAlert.rule_name || "—"}</span>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Tags */}
                  {selectedAlert.tags && selectedAlert.tags.length > 0 && (
                    <Card>
                      <CardHeader className="pb-2">
                        <div className="flex items-center gap-2">
                          <Tag className="h-4 w-4 text-muted-foreground" />
                          <CardTitle className="text-sm font-medium">Tags</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <div className="flex flex-wrap gap-2">
                          {selectedAlert.tags.map((tag, index) => (
                            <Badge key={index} variant="secondary" className="text-xs">
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </TabsContent>

                <TabsContent value="iocs" className="space-y-4 mt-4">
                  <AlertIocPanel iocs={selectedAlert.iocs} />
                </TabsContent>

                <TabsContent value="related" className="space-y-4 mt-4">
                  {/* Related Incidents */}
                  <Card>
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-sm font-medium">Related Incidents</CardTitle>
                        <Badge variant="secondary">{relationships?.incidents?.count || 0}</Badge>
                      </div>
                    </CardHeader>
                    <CardContent>
                      {relationships?.incidents?.items &&
                      relationships.incidents.items.length > 0 ? (
                        <div className="space-y-2">
                          {relationships.incidents.items.map((incident) => (
                            <div
                              key={incident.id}
                              className="flex items-center justify-between p-2 rounded-lg border bg-card hover:bg-accent/50 cursor-pointer"
                              onClick={() => router.push(`/incidents/${incident.id}`)}
                            >
                              <span className="text-sm truncate max-w-[350px]">
                                {incident.title}
                              </span>
                              <ChevronRight className="h-4 w-4 text-muted-foreground" />
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm text-muted-foreground">
                          No related incidents found
                        </p>
                      )}
                    </CardContent>
                  </Card>

                  {/* Similar Alerts */}
                  <Card>
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-sm font-medium">Similar Alerts</CardTitle>
                        <Badge variant="secondary">{relationships?.similar?.count || 0}</Badge>
                      </div>
                    </CardHeader>
                    <CardContent>
                      {relationships?.similar?.items &&
                      relationships.similar.items.length > 0 ? (
                        <div className="space-y-2">
                          {relationships.similar.items.map((alert) => (
                            <div
                              key={alert.id}
                              className="flex items-center justify-between p-2 rounded-lg border bg-card hover:bg-accent/50 cursor-pointer"
                              onClick={() => alert.id && updateSelectedAlert(alert.id)}
                            >
                              <span className="text-sm font-mono">{alert.source_ip || alert.title || "Unknown"}</span>
                              <ChevronRight className="h-4 w-4 text-muted-foreground" />
                            </div>
                          ))}
                          {selectedAlert.source_ip && relationships.similar.count > relationships.similar.items.length && (
                            <Button
                              variant="outline"
                              size="sm"
                              className="w-full mt-2"
                              onClick={() =>
                                router.push(`/search?q=${selectedAlert.source_ip}`)
                              }
                            >
                              Search related IP
                            </Button>
                          )}
                        </div>
                      ) : (
                        <p className="text-sm text-muted-foreground">No similar alerts found</p>
                      )}
                    </CardContent>
                  </Card>
                </TabsContent>
              </Tabs>
            </>
          ) : null}
        </SheetContent>
      </Sheet>
    </div>
  );
}

export default function AlertsPage() {
  return (
    <Suspense fallback={<ListPageSkeleton filterCount={6} />}>
      <AlertsPageInner />
    </Suspense>
  );
}
