"use client";
import { ListPageSkeleton } from "@/components/page-skeletons";

import { useState, useCallback, useMemo, Suspense } from "react";
import useSWR from "swr";
import { useRouter, useSearchParams } from "next/navigation";
import { formatAbsoluteDateTime, getEventTimestamp } from "@/lib/time";
import { TimeFilter, timePresetToRange, type TimePreset } from "@/components/time-filter";
import { X, ArrowRight, Clock, Server, Globe, AlertTriangle, Monitor, Eye } from "lucide-react";
import {
  investigationsAPI,
  type Investigation,
  type InvestigationListResponse,
  type InvestigationStats,
} from "@/lib/api";
import { useWSSubscription, type WSMessage } from "@/lib/websocket";
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
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const statusOptions = [
  { value: "all", label: "All Statuses" },
  { value: "pending", label: "Pending" },
  { value: "running", label: "Running" },
  { value: "awaiting_approval", label: "Awaiting Approval" },
  { value: "manual_review_required", label: "Manual Review" },
  { value: "approved", label: "Approved" },
  { value: "declined", label: "Declined" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
  { value: "archived", label: "Archived" },
];

const sourceOptions = [
  { value: "all", label: "All Sources" },
  { value: "manual", label: "Manual" },
  { value: "auto", label: "Auto" },
  { value: "performance", label: "Performance" },
  { value: "general", label: "General" },
];

function parseSourceIps(sourceIps: string | string[] | null | undefined): string[] {
  if (Array.isArray(sourceIps)) return sourceIps;
  if (typeof sourceIps === "string") return sourceIps.split(",").map((s) => s.trim()).filter(Boolean);
  return [];
}

function InvestigationsPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { selectedAssetId } = useSelectedAsset();
  const [offset, setOffset] = useState(0);
  const [status, setStatus] = useState(searchParams.get("status") || "all");
  const [source, setSource] = useState(searchParams.get("source") || "all");
  const [timePreset, setTimePreset] = useState<TimePreset>((searchParams.get("time_preset") as TimePreset) || "all");
  const limit = 20;

  const timeRange = useMemo(() => timePresetToRange(timePreset), [timePreset]);

  const { data, error, isLoading, mutate } = useSWR<InvestigationListResponse>(
    ["investigations", offset, status, source, timePreset, selectedAssetId],
    () =>
      investigationsAPI.list({
        limit,
        offset,
        status: status !== "all" ? status : undefined,
        source: source !== "all" ? source : undefined,
        asset_id: selectedAssetId || undefined,
        ...timeRange,
      }),
    { refreshInterval: 15000 }
  );

  const { data: stats, error: statsError } = useSWR<InvestigationStats>(
    ["investigations-stats", selectedAssetId],
    () => investigationsAPI.getStats(selectedAssetId || undefined),
    { refreshInterval: 30000 }
  );

  const handleWSUpdate = useCallback((message: WSMessage) => {
    mutate();
  }, [mutate]);

  useWSSubscription("investigation_updated", handleWSUpdate);

  const investigations = data?.investigations || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  const handlePageChange = (page: number) => {
    setOffset((page - 1) * limit);
  };

  const pendingApprovals = stats?.awaiting_approval || 0;

  const columns = [
    {
      key: "severity",
      header: "Severity",
      cell: (inv: Investigation) => (
        <SeverityBadge severity={inv.incident_severity || "medium"} />
      ),
      className: "w-28",
    },
    {
      key: "status",
      header: "Status",
      cell: (inv: Investigation) => <StatusBadge status={inv.status} />,
      className: "w-40",
    },
    {
      key: "incident",
      header: "Incident",
      cell: (inv: Investigation) => {
        const ips = parseSourceIps(inv.source_ips);
        const sourceBadge = (() => {
          const source = inv.source || "general";
          if (source === "auto") {
            return <Badge variant="secondary" className="text-xs">Auto</Badge>;
          }
          if (source === "manual") {
            return <Badge className="bg-blue-500 text-white text-xs hover:bg-blue-600">Manual</Badge>;
          }
          if (source === "performance") {
            return <Badge className="bg-orange-500 text-white text-xs hover:bg-orange-600">Performance</Badge>;
          }
          return <Badge variant="outline" className="text-xs">{source}</Badge>;
        })();
        const safetyBadge = inv.execution_mode === "diagnostic_only" ? (
          <Badge className="bg-blue-500 text-white text-xs hover:bg-blue-600">
            <Eye className="mr-0.5 h-2 w-2" />
            Diagnostic
          </Badge>
        ) : null;
        return (
          <div className="max-w-md">
            <div className="flex items-center gap-2">
              <p className="truncate font-medium">{inv.incident_title}</p>
              {sourceBadge}
              {safetyBadge}
            </div>
            <div className="flex items-center gap-2 mt-1">
              {inv.target_host && (
                <Badge variant="secondary" className="text-xs">
                  <Server className="mr-1 h-2 w-2" />
                  {inv.target_host}
                </Badge>
              )}
              {inv.target_os && (
                <Badge variant="outline" className="text-xs">
                  <Monitor className="mr-1 h-2 w-2" />
                  {inv.target_os}
                </Badge>
              )}
              {inv.status === "running" && inv.run?.current_phase && (
                <StatusBadge status={inv.run.current_phase} className="text-xs" />
              )}
              {ips.length > 0 && (
                <span className="text-xs text-muted-foreground font-mono">
                  {ips[0]}
                  {ips.length > 1 && ` +${ips.length - 1}`}
                </span>
              )}
            </div>
          </div>
        );
      },
    },
    {
      key: "incident_link",
      header: "Incident ID",
      cell: (inv: Investigation) => (
        <Badge
          variant="outline"
          className="cursor-pointer font-mono text-xs"
          onClick={(e) => {
            e.stopPropagation();
            router.push(`/incidents/${inv.local_incident_id || inv.incident_id}`);
          }}
        >
          {inv.local_incident_id || inv.incident_id}
        </Badge>
      ),
      className: "w-32",
    },
    {
      key: "created",
      header: "Created",
      cell: (inv: Investigation) => {
        const ts = getEventTimestamp(inv, "investigation");
        return (
          <span className="text-sm text-muted-foreground">
            {formatAbsoluteDateTime(ts)}
          </span>
        );
      },
      className: "w-32",
    },
    {
      key: "actions",
      header: "",
      cell: (inv: Investigation) => (
        <Button
          variant={inv.status === "awaiting_approval" ? "default" : "ghost"}
          size="sm"
          onClick={(e) => {
            e.stopPropagation();
            router.push(`/investigations/${inv.id}`);
          }}
        >
          {inv.status === "awaiting_approval" ? "Review" : "View"}
          <ArrowRight className="ml-1 h-4 w-4" />
        </Button>
      ),
      className: "w-28",
    },
  ];

  const clearFilters = () => {
    setStatus("all");
    setSource("all");
    setTimePreset("all");
    setOffset(0);
  };

  const hasFilters = status !== "all" || source !== "all" || timePreset !== "all";

  return (
    <div className="flex flex-col">
      <PageHeader
        title="Investigations"
        description="AI-powered security investigations with automated playbooks"
        onRefresh={() => mutate()}
        isLoading={isLoading}
        actions={
          <div className="flex items-center gap-2">
            <Select value={status} onValueChange={(v) => { setStatus(v); setOffset(0); }}>
              <SelectTrigger className="w-44 max-sm:w-full">
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
            <Select value={source} onValueChange={(v) => { setSource(v); setOffset(0); }}>
              <SelectTrigger className="w-40 max-sm:w-full">
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

      <div className="flex-1 space-y-6 p-6">
        {/* Error State */}
        {(error || statsError) && (
          <Card className="border-destructive/50 bg-destructive/5">
            <CardContent className="flex items-center gap-3 py-4">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              <div>
                <p className="font-medium text-destructive">Failed to load data</p>
                <p className="text-sm text-muted-foreground">
                  {error?.message || statsError?.message || "Please try again later."}
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Pending Approvals Alert */}
        {pendingApprovals > 0 && status === "all" && !error && !statsError && (
          <Card className="border-warning/50 bg-warning/5">
            <CardContent className="flex items-center justify-between py-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-warning/10">
                  <Clock className="h-5 w-5 text-warning" />
                </div>
                <div>
                  <p className="font-medium">
                    {pendingApprovals} investigation{pendingApprovals > 1 ? "s" : ""} awaiting approval
                  </p>
                  <p className="text-sm text-muted-foreground">
                    Review AI-generated playbooks before execution
                  </p>
                </div>
              </div>
              <Button
                variant="outline"
                className="border-warning text-warning hover:bg-warning/10"
                onClick={() => setStatus("awaiting_approval")}
              >
                Review Now
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Status Overview */}
        <div className="grid gap-4 md:grid-cols-4 lg:grid-cols-8">
          {[
            { key: "pending", label: "Pending", count: stats?.pending || 0 },
            { key: "running", label: "Running", count: stats?.running || 0 },
            { key: "awaiting_approval", label: "Awaiting", count: stats?.awaiting_approval || 0 },
            { key: "manual_review_required", label: "Manual Review", count: stats?.manual_review_required || 0 },
            { key: "approved", label: "Approved", count: stats?.approved || 0 },
            { key: "completed", label: "Completed", count: stats?.completed || 0 },
            { key: "failed", label: "Failed", count: stats?.failed || 0 },
            { key: "declined", label: "Declined", count: stats?.declined || 0 },
            { key: "archived", label: "Archived", count: stats?.archived || 0 },
          ].map((item) => {
            const isActive = status === item.key;

            return (
              <Card
                key={item.key}
                className={cn(
                  "cursor-pointer transition-all hover:shadow-md",
                  isActive && "ring-2 ring-primary"
                )}
                onClick={() => setStatus(isActive ? "all" : item.key)}
              >
                <CardContent className="pt-4 pb-3">
                  <div className="flex flex-col items-center gap-1">
                    <span className="text-2xl font-bold">{item.count}</span>
                    <StatusBadge status={item.key} className="text-xs" />
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        <DataTable
          columns={columns}
          data={investigations}
          page={currentPage}
          totalPages={totalPages}
          onPageChange={handlePageChange}
          onRowClick={(inv) => router.push(`/investigations/${inv.id}`)}
          isLoading={isLoading}
          emptyMessage="No investigations found"
        />
      </div>
    </div>
  );
}

export default function InvestigationsPage() {
  return (
    <Suspense fallback={<ListPageSkeleton filterCount={3} />}>
      <InvestigationsPageInner />
    </Suspense>
  );
}
