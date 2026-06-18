"use client";

import { useState, useCallback, useMemo } from "react";
import useSWR from "swr";
import { useRouter } from "next/navigation";
import { formatAbsoluteDateTime, getEventTimestamp } from "@/lib/time";
import { TimeFilter, timePresetToRange, type TimePreset } from "@/components/time-filter";
import {
  HardDrive,
  Server,
  ArrowRight,
  ThumbsUp,
  ThumbsDown,
  Search,
  SlidersHorizontal,
  X,
  Gauge,
  AlertTriangle,
  Zap,
} from "lucide-react";
import {
  infrastructureAPI,
  type InfrastructureInvestigationListResponse,
} from "@/lib/api";
import { useWSSubscription } from "@/lib/websocket";
import { useSelectedAsset } from "@/lib/asset-context";
import { PageHeader } from "@/components/page-header";
import { DataTable } from "@/components/data-table";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { StatsOverview, ResourceTypeBreakdown } from "@/components/infrastructure/stats-overview";
import { ResourceTypeIcon, ResourceColor } from "@/components/infrastructure/resource-gauge";

const statusOptions = [
  { value: "all", label: "All Statuses" },
  { value: "diagnosing", label: "Diagnosing" },
  { value: "findings_ready", label: "Findings Ready" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "escalated", label: "Escalated" },
  { value: "archived", label: "Archived" },
];

const severityOptions = [
  { value: "all", label: "All Severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const resourceTypeOptions = [
  { value: "all", label: "All Resources" },
  { value: "cpu", label: "CPU" },
  { value: "memory", label: "Memory" },
  { value: "disk", label: "Disk" },
  { value: "network", label: "Network" },
];

export default function InfrastructureInvestigationsPage() {
  const router = useRouter();
  const { selectedAssetId } = useSelectedAsset();
  const [offset, setOffset] = useState(0);
  const [status, setStatus] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [resourceType, setResourceType] = useState("all");
  const [hostSearch, setHostSearch] = useState("");
  const [timePreset, setTimePreset] = useState<TimePreset>("all");
  const limit = 20;

  const timeRange = useMemo(() => timePresetToRange(timePreset), [timePreset]);

  const { data, error, isLoading, mutate } = useSWR<InfrastructureInvestigationListResponse>(
    ["infrastructure-investigations", offset, status, severity, resourceType, hostSearch, timePreset, selectedAssetId],
    () =>
      infrastructureAPI.list({
        limit,
        offset,
        status: status !== "all" ? status : undefined,
        severity: severity !== "all" ? severity : undefined,
        resource_type: resourceType !== "all" ? resourceType : undefined,
        host: hostSearch.trim() || undefined,
        asset_id: selectedAssetId || undefined,
        ...timeRange,
      }),
    { refreshInterval: 15000 }
  );

  const { data: stats, isLoading: statsLoading } = useSWR(
    "infrastructure-stats",
    () => infrastructureAPI.getStats(),
    { refreshInterval: 30000 }
  );

  const [incomingAlert, setIncomingAlert] = useState<{host: string; resource: string; severity: string} | null>(null);

  const handleWSUpdate = useCallback(() => {
    mutate();
  }, [mutate]);

  const handlePerformanceAlert = useCallback((msg: any) => {
    const alert = msg.data?.alert;
    if (alert) {
      setIncomingAlert({
        host: alert.host || alert.hostname || "unknown",
        resource: alert.resource_type || alert.anomaly_type || "unknown",
        severity: alert.severity || "medium",
      });
      // Auto-clear after 8 seconds
      setTimeout(() => setIncomingAlert(null), 8000);
    }
    // Immediately refresh list
    mutate();
  }, [mutate]);

  useWSSubscription("investigation_updated", handleWSUpdate);
  useWSSubscription("performance_alert", handlePerformanceAlert);

  const investigations = data?.investigations || [];
  const total = data?.total || 0;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const currentPage = Math.floor(offset / limit) + 1;

  const handlePageChange = (page: number) => {
    setOffset((page - 1) * limit);
  };

  const hasActiveFilters = status !== "all" || severity !== "all" || resourceType !== "all" || hostSearch.trim() !== "" || timePreset !== "all";

  const clearFilters = () => {
    setStatus("all");
    setSeverity("all");
    setResourceType("all");
    setHostSearch("");
    setTimePreset("all");
    setOffset(0);
  };

  const filterActions = (
    <div className="flex items-center gap-2">
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search host..."
          value={hostSearch}
          onChange={(e) => { setHostSearch(e.target.value); setOffset(0); }}
          className="pl-9 w-44"
        />
        {hostSearch && (
          <button
            onClick={() => setHostSearch("")}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </div>

      <Select value={status} onValueChange={(v) => { setStatus(v); setOffset(0); }}>
        <SelectTrigger className="w-36 max-sm:w-full">
          <SelectValue placeholder="Status" />
        </SelectTrigger>
        <SelectContent>
          {statusOptions.map((opt) => (
            <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
          ))}
        </SelectContent>
      </Select>

      <Select value={severity} onValueChange={(v) => { setSeverity(v); setOffset(0); }}>
        <SelectTrigger className="w-36 max-sm:w-full">
          <SelectValue placeholder="Severity" />
        </SelectTrigger>
        <SelectContent>
          {severityOptions.map((opt) => (
            <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
          ))}
        </SelectContent>
      </Select>

      <Select value={resourceType} onValueChange={(v) => { setResourceType(v); setOffset(0); }}>
        <SelectTrigger className="w-36 max-sm:w-full">
          <SelectValue placeholder="Resource" />
        </SelectTrigger>
        <SelectContent>
          {resourceTypeOptions.map((opt) => (
            <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
          ))}
        </SelectContent>
      </Select>

      <TimeFilter
        value={timePreset}
        onChange={(v) => {
          setTimePreset(v);
          setOffset(0);
        }}
      />

      {hasActiveFilters && (
        <Button variant="ghost" size="sm" onClick={clearFilters} className="gap-1.5 h-9">
          <SlidersHorizontal className="h-3.5 w-3.5" />
          Clear
        </Button>
      )}
    </div>
  );

  const columns = useMemo(
    () => [
      {
        key: "resource",
        header: "Resource",
        cell: (inv: any) => (
          <div className="flex items-center gap-2">
            <div className={cn("flex h-8 w-8 items-center justify-center rounded-md border", ResourceColor(inv.resource_type))}>
              <ResourceTypeIcon type={inv.resource_type} className="h-4 w-4" />
            </div>
            <div className="flex flex-col">
              <span className="text-xs font-medium capitalize">{inv.resource_type || "unknown"}</span>
              {inv.affected_service && (
                <span className="text-xs text-muted-foreground">{inv.affected_service}</span>
              )}
            </div>
          </div>
        ),
        className: "w-28",
      },
      {
        key: "incident_title",
        header: "Alert",
        cell: (inv: any) => (
          <div className="flex flex-col gap-0.5">
            <span className="font-medium text-sm line-clamp-1">{inv.incident_title}</span>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Server className="h-3 w-3" />
              {inv.target_host || "unknown"}
            </div>
          </div>
        ),
      },
      {
        key: "value",
        header: "Value / Threshold",
        cell: (inv: any) => {
          const pct = inv.threshold ? (inv.current_value / inv.threshold) * 100 : 0;
          const color =
            pct >= 100 ? "bg-destructive" : pct >= 80 ? "bg-warning" : pct >= 60 ? "bg-chart-4" : "bg-success";
          return (
            <div className="flex flex-col gap-1 w-28">
              <div className="flex items-center justify-between text-xs">
                <span className="font-mono font-medium">{inv.current_value?.toFixed?.(1) ?? "—"}</span>
                <span className="text-muted-foreground">/ {inv.threshold?.toFixed?.(1) ?? "—"}</span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
                <div className={cn("h-full rounded-full transition-all", color)} style={{ width: `${Math.min(100, pct)}%` }} />
              </div>
            </div>
          );
        },
        className: "w-36",
      },
      {
        key: "incident_severity",
        header: "Severity",
        cell: (inv: any) => <SeverityBadge severity={inv.incident_severity} />,
        className: "w-24",
      },
      {
        key: "status",
        header: "Status",
        cell: (inv: any) => <StatusBadge status={inv.status} />,
        className: "w-32",
      },
      {
        key: "created_at",
        header: "Created",
        cell: (inv: any) => (
          <span className="text-xs text-muted-foreground whitespace-nowrap">
            {formatAbsoluteDateTime(getEventTimestamp(inv, "infrastructure"))}
          </span>
        ),
        className: "w-24",
      },
      {
        key: "actions",
        header: "",
        cell: (inv: any) => (
          <div className="flex items-center justify-end gap-1">
            {inv.status === "findings_ready" && (
              <Badge variant="default" className="text-xs h-5 mr-1">Review</Badge>
            )}
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={(e) => {
                e.stopPropagation();
                router.push(`/infrastructure/investigations/${inv.id}`);
              }}
            >
              <ArrowRight className="h-4 w-4" />
            </Button>
          </div>
        ),
        className: "w-24",
      },
    ],
    [router]
  );

  return (
    <div className="flex flex-col">
      <PageHeader
        title="Infrastructure Investigations"
        description="Resource anomaly investigations — CPU, Memory, Disk, Network"
        icon={HardDrive}
        isLive
        onRefresh={() => mutate()}
        isLoading={isLoading}
        actions={filterActions}
      />

      <div className="flex-1 space-y-4 p-6">
        {incomingAlert && (
          <div className="rounded-lg border bg-amber-50 border-amber-200 p-3 flex items-center gap-3 animate-in fade-in slide-in-from-top-2 duration-300">
            <Zap className="h-5 w-5 text-amber-600 shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-amber-900">
                New performance alert detected on {incomingAlert.host}
              </p>
              <p className="text-xs text-amber-700">
                {incomingAlert.resource} — severity {incomingAlert.severity}. Investigation starting...
              </p>
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 text-amber-800 hover:text-amber-900 hover:bg-amber-100"
              onClick={() => setIncomingAlert(null)}
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          </div>
        )}

        <StatsOverview stats={stats ?? null} isLoading={statsLoading} />
        <ResourceTypeBreakdown investigations={investigations} />

        <DataTable
          columns={columns}
          data={investigations}
          isLoading={isLoading}
          page={currentPage}
          totalPages={totalPages}
          onPageChange={handlePageChange}
          onRowClick={(inv) => router.push(`/infrastructure/investigations/${inv.id}`)}
          emptyMessage={
            hasActiveFilters
              ? "No investigations match your filters"
              : "No infrastructure investigations yet"
          }
        />
      </div>
    </div>
  );
}
