"use client";

import { useState, useCallback } from "react";
import useSWR from "swr";
import { AlertTriangle, FileWarning, Search, Clock, Shield, EyeOff } from "lucide-react";
import { useRouter } from "next/navigation";
import { 
  dashboardAPI, 
  investigationsAPI,
  ariaAlertsAPI,
  type DashboardSummary, 
  type QuickStats,
  type InvestigationStats,
  type TrendData,
  type SeverityCount,
  type ActivityItem,
  type AriaAlertStats,
  type SourceBreakdown,
  type MitreCoverage,
  type ResponseMetrics,
  type GeoThreats,
} from "@/lib/api";
import { useWebSocket, useWSSubscription, type WSMessage } from "@/lib/websocket";
import { useSelectedAsset } from "@/lib/asset-context";
import { StatCard, StatCardSkeleton } from "@/components/dashboard/stat-card";
import { AlertsChart } from "@/components/dashboard/alerts-chart";
import { SeverityChart } from "@/components/dashboard/severity-chart";
import { ActivityFeed } from "@/components/dashboard/activity-feed";
import { QuickActions } from "@/components/dashboard/quick-actions";
import { AriaHealthWidget } from "@/components/dashboard/aria-health-widget";
import { SourceBreakdownWidget } from "@/components/dashboard/source-breakdown";
import { MitreCoverageWidget } from "@/components/dashboard/mitre-coverage";
import { ResponseMetricsWidget } from "@/components/dashboard/response-metrics";
import { GeoThreatWidget } from "@/components/dashboard/geo-threats";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { SearchIcon, RefreshCw } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { SectionHeader } from "@/components/section-header";
import { EmptyState } from "@/components/empty-state";

// Types for combined dashboard data
interface DashboardData {
  quickStats: QuickStats;
  summary?: DashboardSummary;
  investigationStats?: InvestigationStats;
  alertsTrend?: TrendData[];
  severityBreakdown?: SeverityCount[];
  recentActivity?: ActivityItem[];
  criticalAlertsCount?: number;
  ariaAlertStats?: AriaAlertStats;
  sourceBreakdown?: SourceBreakdown;
  mitreCoverage?: MitreCoverage;
  responseMetrics?: ResponseMetrics;
  geoThreats?: GeoThreats;
  errors?: string[];
}

// Map investigations to activity items
function computeRecentActivity(
  investigations: {
    id: string;
    incident_title?: string;
    status?: string;
    created_at?: string;
    updated_at?: string;
  }[]
): ActivityItem[] {
  return investigations
    .filter((inv) => inv.updated_at || inv.created_at)
    .map((inv) => ({
      id: inv.id,
      type: "investigation",
      message: `Investigation for "${inv.incident_title || "Untitled"}" — ${inv.status || "unknown"}`,
      timestamp: inv.updated_at || inv.created_at || new Date().toISOString(),
    }));
}

// Fetch all dashboard data using real APIs only with partial failure tolerance
async function fetchDashboardData(range: string, asset_id?: string): Promise<DashboardData> {
  const [
    quickStatsRes,
    summaryRes,
    investigationStatsRes,
    trendsRes,
    investigationsRes,
    ariaAlertStatsRes,
    sourceBreakdownRes,
    mitreCoverageRes,
    responseMetricsRes,
    geoThreatsRes,
  ] = await Promise.allSettled([
    dashboardAPI.getQuickStats(range, asset_id),
    dashboardAPI.getSummary(range, asset_id),
    investigationsAPI.getStats(asset_id),
    dashboardAPI.getTrends(range, asset_id),
    investigationsAPI.list({ limit: 10, asset_id }),
    ariaAlertsAPI.getStats(asset_id),
    dashboardAPI.getSourceBreakdown(range, asset_id),
    dashboardAPI.getMitreCoverage(range, asset_id),
    dashboardAPI.getResponseMetrics(range, asset_id),
    dashboardAPI.getGeoThreats(range, asset_id),
  ]);

  const quickStats = quickStatsRes.status === "fulfilled" ? quickStatsRes.value : { alerts: 0, incidents: 0, investigations: 0, archives: 0 };
  const summary = summaryRes.status === "fulfilled" ? summaryRes.value : undefined;
  const investigationStats = investigationStatsRes.status === "fulfilled" ? investigationStatsRes.value : undefined;
  const trendsResValue = trendsRes.status === "fulfilled" ? trendsRes.value : { range: "24h", buckets: [] };
  const investigationsResValue = investigationsRes.status === "fulfilled" ? investigationsRes.value : { investigations: [] as unknown[], total: 0 };
  const ariaAlertStats = ariaAlertStatsRes.status === "fulfilled" ? ariaAlertStatsRes.value : undefined;
  const sourceBreakdown = sourceBreakdownRes.status === "fulfilled" ? sourceBreakdownRes.value : undefined;
  const mitreCoverage = mitreCoverageRes.status === "fulfilled" ? mitreCoverageRes.value : undefined;
  const responseMetrics = responseMetricsRes.status === "fulfilled" ? responseMetricsRes.value : undefined;
  const geoThreats = geoThreatsRes.status === "fulfilled" ? geoThreatsRes.value : undefined;

  // Use server-side trends for accurate 24h alert distribution
  const alertsTrend: TrendData[] = (trendsResValue.buckets || []).map((b: any) => ({
    timestamp: b.time,
    count: b.count,
  }));

  // Use summary incident severity breakdown (all open incidents, not just 100)
  // Ensure all severity levels are always present so the chart never hides categories
  const severityBreakdown: SeverityCount[] = (() => {
    const base: SeverityCount[] = [
      { severity: "critical", count: 0 },
      { severity: "high", count: 0 },
      { severity: "medium", count: 0 },
      { severity: "low", count: 0 },
    ];
    if (!summary?.incidents?.by_severity) return base;
    const apiCounts = summary.incidents.by_severity as Record<string, number>;
    return base.map((item) => ({
      severity: item.severity,
      count: apiCounts[item.severity] || 0,
    }));
  })();

  const recentActivity = computeRecentActivity((investigationsResValue.investigations || []) as { id: string; incident_title?: string; status?: string; created_at?: string; updated_at?: string }[]);
  const criticalAlertsCount = quickStats.critical_alerts ?? 0;

  const errors: string[] = [];
  if (quickStatsRes.status === "rejected") errors.push("Quick stats unavailable");
  if (summaryRes.status === "rejected") errors.push("Summary unavailable");
  if (investigationStatsRes.status === "rejected") errors.push("Investigation stats unavailable");
  if (trendsRes.status === "rejected") errors.push("Alerts trend data unavailable");
  if (investigationsRes.status === "rejected") errors.push("Recent activity unavailable");
  if (ariaAlertStatsRes.status === "rejected") errors.push("ARIA health unavailable");
  if (sourceBreakdownRes.status === "rejected") errors.push("Source breakdown unavailable");
  if (mitreCoverageRes.status === "rejected") errors.push("MITRE coverage unavailable");
  if (responseMetricsRes.status === "rejected") errors.push("Response metrics unavailable");
  if (geoThreatsRes.status === "rejected") errors.push("Geo threats unavailable");

  return {
    quickStats,
    summary,
    investigationStats,
    alertsTrend,
    severityBreakdown,
    recentActivity,
    criticalAlertsCount,
    ariaAlertStats,
    sourceBreakdown,
    mitreCoverage,
    responseMetrics,
    geoThreats,
    errors: errors.length > 0 ? errors : undefined,
  };
}

export default function DashboardPage() {
  const router = useRouter();
  const [searchQuery, setSearchQuery] = useState("");
  const [timeRange, setTimeRange] = useState<"15m" | "1h" | "24h" | "7d">("24h");
  const { selectedAssetId } = useSelectedAsset();

  const { data, error, isLoading, mutate } = useSWR<DashboardData>(
    ["dashboard-data", timeRange, selectedAssetId],
    () => fetchDashboardData(timeRange, selectedAssetId || undefined),
    {
      refreshInterval: 30000,
    }
  );

  // Handle real-time updates
  const handleWSUpdate = useCallback((_: WSMessage) => {
    mutate();
  }, [mutate]);

  useWSSubscription("investigation_updated", handleWSUpdate);
  useWSSubscription("performance_alert", handleWSUpdate);

  const { isConnected } = useWebSocket();

  const quickStats = data?.quickStats;
  const summary = data?.summary;
  const investigationStats = data?.investigationStats;
  const alertsTrend = data?.alertsTrend;
  const severityBreakdown = data?.severityBreakdown;
  const recentActivity = data?.recentActivity;
  const ariaAlertStats = data?.ariaAlertStats;
  const sourceBreakdown = data?.sourceBreakdown;
  const mitreCoverage = data?.mitreCoverage;
  const responseMetrics = data?.responseMetrics;
  const geoThreats = data?.geoThreats;

  // Calculate critical alerts from real alerts data
  const criticalAlerts = data?.criticalAlertsCount ?? 0;
  const openIncidents = summary?.incidents?.open ?? quickStats?.incidents ?? 0;
  const pendingApprovals = quickStats?.pending_approvals ?? investigationStats?.awaiting_approval ?? 0;

  const rangeLabel = {
    "15m": "Last 15 minutes",
    "1h": "Last hour",
    "24h": "Last 24 hours",
    "7d": "Last 7 days",
  }[timeRange];

  // Format delta percentage for display
  function fmtDelta(pct: number | null | undefined, current: number): string | undefined {
    if (pct === null || pct === undefined) {
      if (current > 0) return "New activity vs previous period";
      return "No change vs previous period";
    }
    if (pct === 0) return "No change vs previous period";
    const sign = pct > 0 ? "+" : "";
    return `${sign}${pct}% vs previous period`;
  }

  return (
    <div className="flex flex-col">
      {/* Header */}
      <header className="sticky top-0 z-10 border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="flex h-16 items-center justify-between px-6 flex-wrap gap-y-2">
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Security Dashboard</h1>
            <p className="text-xs text-muted-foreground">
              Real-time security operations overview
            </p>
          </div>
          <div className="flex items-center gap-3">
            <div className="relative w-64">
              <SearchIcon className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search alerts, incidents..."
                aria-label="Search alerts and incidents"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 pr-16"
                onKeyDown={(e) => {
                  if (e.key === "Enter" && searchQuery) {
                    router.push(`/search?q=${encodeURIComponent(searchQuery)}`);
                  }
                }}
              />
              <kbd className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 hidden sm:inline-flex h-5 select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-xs font-medium text-muted-foreground opacity-100">
                <span className="text-xs">⌘</span>K
              </kbd>
            </div>
            <Select value={timeRange} onValueChange={(v) => setTimeRange(v as "15m" | "1h" | "24h" | "7d")}>
              <SelectTrigger className="w-[130px] h-9 text-sm">
                <SelectValue placeholder="Range" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="15m">Last 15m</SelectItem>
                <SelectItem value="1h">Last 1h</SelectItem>
                <SelectItem value="24h">Last 24h</SelectItem>
                <SelectItem value="7d">Last 7d</SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant="outline"
              size="icon"
              onClick={() => mutate()}
              disabled={isLoading}
            >
              <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} aria-label="Refresh dashboard" />
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 space-y-6 p-6 dark:ambient-glow">
        {(error || data?.errors) && (
          <div className={cn(
            "rounded-lg border p-4",
            error ? "border-destructive/50 bg-destructive/10 text-destructive" : "border-warning/50 bg-warning/10 text-warning"
          )}>
            <p className="font-medium">
              {error ? "Failed to load dashboard data" : "Some dashboard data could not be loaded"}
            </p>
            <p className="text-sm">
              {error instanceof Error ? error.message : data?.errors?.join(" • ")}
            </p>
          </div>
        )}

        {/* SOC Overview */}
        <SectionHeader title="SOC Overview" />
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 stagger-children">
          {isLoading || !quickStats ? (
            <>
              <StatCardSkeleton />
              <StatCardSkeleton />
              <StatCardSkeleton />
              <StatCardSkeleton />
              <StatCardSkeleton />
              <StatCardSkeleton />
            </>
          ) : (
            <>
              <StatCard
                title="Total Alerts"
                value={quickStats.alerts}
                subtitle={rangeLabel}
                delta={fmtDelta(quickStats.alerts_delta_pct, quickStats.alerts)}
                icon={AlertTriangle}
                onClick={() => router.push("/alerts")}
              />
              <StatCard
                title="Critical Alerts"
                value={criticalAlerts}
                subtitle="Requires immediate action"
                delta={fmtDelta(quickStats.critical_alerts_delta_pct, criticalAlerts)}
                icon={Shield}
                variant="critical"
                onClick={() => router.push("/alerts?severity=critical")}
              />
              <StatCard
                title="Open Incidents"
                value={openIncidents}
                subtitle="Under investigation"
                icon={FileWarning}
                variant="warning"
                onClick={() => router.push("/incidents?status=open")}
              />
              <StatCard
                title="Active Investigations"
                value={quickStats.investigations}
                subtitle="AI analysis in progress"
                icon={Search}
                onClick={() => router.push("/investigations?status=running")}
              />
              <StatCard
                title="Pending Approvals"
                value={pendingApprovals}
                subtitle="Playbooks awaiting review"
                icon={Clock}
                variant={pendingApprovals > 0 ? "warning" : "success"}
                onClick={() => router.push("/investigations?status=awaiting_approval")}
              />
              <StatCard
                title="Suppressed"
                value={(quickStats.whitelisted_alerts ?? 0) + (quickStats.whitelisted_incidents ?? 0)}
                subtitle="Whitelisted alerts & incidents"
                delta={fmtDelta(quickStats.whitelisted_alerts_delta_pct, quickStats.whitelisted_alerts ?? 0)}
                icon={EyeOff}
                variant="default"
                onClick={() => router.push("/alerts?whitelisted=true")}
              />
            </>
          )}
        </div>

        {/* Monitoring */}
        <SectionHeader title="Monitoring" />
        <div className="grid gap-4 lg:grid-cols-3">
          {isLoading || !alertsTrend ? (
            <div className="lg:col-span-2 h-full rounded-xl border bg-card p-6">
              <Skeleton className="mb-4 h-5 w-32" />
              <Skeleton className="h-full w-full" />
            </div>
          ) : alertsTrend.length === 0 ? (
            <EmptyState
              icon={AlertTriangle}
              title="No alert activity"
              description={`No alerts were recorded in the ${rangeLabel.toLowerCase()}.`}
              className="lg:col-span-2 h-[320px]"
            />
          ) : (
            <div className="lg:col-span-2 h-full">
              <AlertsChart data={alertsTrend} />
            </div>
          )}

          {isLoading || !severityBreakdown ? (
            <div className="flex flex-col gap-3">
              <div className="rounded-xl border bg-card p-6 flex-1">
                <Skeleton className="mb-4 h-5 w-40" />
                <Skeleton className="h-[200px] w-full" />
              </div>
              <Skeleton className="h-[80px] w-full rounded-xl" />
            </div>
          ) : severityBreakdown.length === 0 ? (
            <div className="flex flex-col gap-3">
              <EmptyState
                icon={FileWarning}
                title="No incident severity data"
                description="No open incidents to break down by severity."
                className="h-[260px]"
              />
              <AriaHealthWidget
                stats={ariaAlertStats}
                error={data?.errors?.some((e) => e.includes("ARIA health"))}
              />
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              <SeverityChart
                data={severityBreakdown}
                onSliceClick={(severity) => router.push(`/incidents?severity=${severity}&status=open`)}
              />
              <AriaHealthWidget
                stats={ariaAlertStats}
                error={data?.errors?.some((e) => e.includes("ARIA health"))}
              />
            </div>
          )}
        </div>

        {/* Threat Intelligence */}
        <SectionHeader title="Threat Intelligence" />
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 items-stretch">
          {isLoading ? (
            <>
              <div className="rounded-xl border bg-card p-6">
                <Skeleton className="mb-4 h-5 w-40" />
                <Skeleton className="h-[140px] w-full" />
              </div>
              <div className="rounded-xl border bg-card p-6">
                <Skeleton className="mb-4 h-5 w-40" />
                <Skeleton className="h-[140px] w-full" />
              </div>
              <div className="rounded-xl border bg-card p-6">
                <Skeleton className="mb-4 h-5 w-40" />
                <Skeleton className="h-[140px] w-full" />
              </div>
            </>
          ) : (
            <>
              <SourceBreakdownWidget
                data={sourceBreakdown}
                error={data?.errors?.some((e) => e.includes("Source breakdown"))}
              />
              <MitreCoverageWidget
                data={mitreCoverage}
                error={data?.errors?.some((e) => e.includes("MITRE coverage"))}
              />
              <ResponseMetricsWidget
                data={responseMetrics}
                error={data?.errors?.some((e) => e.includes("Response metrics"))}
              />
            </>
          )}
        </div>

        {/* Operations */}
        <SectionHeader title="Operations" />
        <div className="grid gap-4 lg:grid-cols-3">
          {/* Left column: Geo Threats + Quick Actions stacked */}
          <div className="flex flex-col gap-4">
            {isLoading ? (
              <div className="rounded-xl border bg-card p-6">
                <Skeleton className="mb-4 h-5 w-40" />
                <Skeleton className="h-[240px] w-full" />
              </div>
            ) : (
              <GeoThreatWidget
                data={geoThreats}
                error={data?.errors?.some((e) => e.includes("Geo threats"))}
              />
            )}

            {isLoading || !investigationStats ? (
              <div className="rounded-xl border bg-card p-6">
                <Skeleton className="mb-4 h-5 w-32" />
                <div className="space-y-3">
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-10 w-full" />
                </div>
              </div>
            ) : (
              <QuickActions
                pendingApprovals={pendingApprovals}
                activeInvestigations={quickStats?.investigations || 0}
              />
            )}
          </div>

          {/* Right wide column: Recent Activity */}
          <div className="lg:col-span-2">
            {isLoading || !recentActivity ? (
              <div className="rounded-xl border bg-card p-6 h-full">
                <Skeleton className="mb-4 h-5 w-32" />
                <div className="space-y-3">
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                </div>
              </div>
            ) : recentActivity.length === 0 ? (
              <EmptyState
                icon={Search}
                title="No recent activity"
                description="Investigation activity will appear here as ARIA processes new events."
                className="h-full min-h-[320px]"
              />
            ) : (
              <ActivityFeed activities={recentActivity} isConnected={isConnected} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
