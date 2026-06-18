"use client";

import { useState, useMemo } from "react";
import useSWR from "swr";
import { useRouter } from "next/navigation";
import { useSelectedAsset } from "@/lib/asset-context";
import { useAuth } from "@/lib/auth-context";
import { formatDistanceToNow } from "date-fns";
import {
  ArrowRight,
  Archive,
  CheckCircle2,
  XCircle,
  TrendingUp,
  Filter,
  Search,
  Clock,
  AlertTriangle,
  Shield,
} from "lucide-react";
import {
  archivesAPI,
  type Archive as ArchiveType,
  type ArchiveListResponse,
  type ArchiveStats,
} from "@/lib/api";
import { PageHeader } from "@/components/page-header";
import { DataTable } from "@/components/data-table";
import { SeverityBadge } from "@/components/severity-badge";
import { FixStatusBadge } from "@/components/fix-status-badge";
import { ErrorState } from "@/components/error-state";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";

function CircularProgress({ value, size = 56, strokeWidth = 5, color = "#10b981" }: { value: number; size?: number; strokeWidth?: number; color?: string }) {
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const offset = circumference - (value / 100) * circumference;
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="currentColor"
          strokeWidth={strokeWidth}
          fill="transparent"
          className="text-muted/30"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth={strokeWidth}
          fill="transparent"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-500"
        />
      </svg>
      <span className="absolute text-xs font-semibold">{Math.round(value)}%</span>
    </div>
  );
}

function SeverityDistributionBar({ stats }: { stats?: ArchiveStats }) {
  const sev = stats?.by_severity || {};
  const total = Object.values(sev).reduce((a, b) => a + (b || 0), 0);
  if (total === 0) return null;

  const colors: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-amber-500",
    low: "bg-blue-400",
  };

  return (
    <div className="space-y-2">
      <div className="flex h-2.5 w-full overflow-hidden rounded-full">
        {["critical", "high", "medium", "low"].map((key) => {
          const count = sev[key as keyof typeof sev] || 0;
          const pct = total > 0 ? (count / total) * 100 : 0;
          if (pct <= 0) return null;
          return (
            <div
              key={key}
              className={colors[key] || "bg-muted"}
              style={{ width: `${pct}%` }}
              title={`${key}: ${count}`}
            />
          );
        })}
      </div>
      <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
        {["critical", "high", "medium", "low"].map((key) => {
          const count = sev[key as keyof typeof sev] || 0;
          if (count === 0) return null;
          return (
            <span key={key} className="inline-flex items-center gap-1">
              <span className={`inline-block h-2 w-2 rounded-full ${colors[key]}`} />
              {key.charAt(0).toUpperCase() + key.slice(1)} ({count})
            </span>
          );
        })}
      </div>
    </div>
  );
}

export default function ArchivesPage() {
  const router = useRouter();
  const [offset, setOffset] = useState(0);
  const [fixStatusFilter, setFixStatusFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [timeRange, setTimeRange] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const limit = 20;

  const { selectedAssetId } = useSelectedAsset();
  const { user } = useAuth();

  // For server_user, always scope to their assigned asset
  const effectiveAssetId = useMemo(() => {
    if (user?.role === "server_user" && user?.asset_id) {
      return user.asset_id;
    }
    return selectedAssetId || undefined;
  }, [user, selectedAssetId]);

  const timeParams = useMemo(() => {
    const now = new Date();
    let time_from: string | undefined;
    const time_to: string | undefined = now.toISOString();
    if (timeRange === "7d") {
      time_from = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
    } else if (timeRange === "30d") {
      time_from = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
    } else if (timeRange === "90d") {
      time_from = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000).toISOString();
    }
    return { time_from, time_to };
  }, [timeRange]);

  const {
    data,
    isLoading,
    error,
    mutate,
  } = useSWR<ArchiveListResponse>(
    ["archives", offset, fixStatusFilter, severityFilter, timeRange, searchQuery, effectiveAssetId],
    () =>
      archivesAPI.list({
        limit,
        offset,
        fix_status: fixStatusFilter !== "all" ? fixStatusFilter : undefined,
        severity: severityFilter !== "all" ? severityFilter : undefined,
        search: searchQuery.trim() || undefined,
        ...timeParams,
        asset_id: effectiveAssetId,
      })
  );

  const { data: stats } = useSWR<ArchiveStats>(
    ["archives-stats", effectiveAssetId],
    () => archivesAPI.getStats(effectiveAssetId),
    { refreshInterval: 60000 }
  );

  const archives = data?.archives || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  const handlePageChange = (page: number) => {
    setOffset((page - 1) * limit);
  };

  const successRate = stats?.fix_success_rate_pct ?? 0;
  const successColor = successRate >= 80 ? "#10b981" : successRate >= 50 ? "#f59e0b" : "#ef4444";

  const columns = [
    {
      key: "severity",
      header: "Severity",
      cell: (archive: ArchiveType) => (
        <SeverityBadge severity={archive.severity} />
      ),
      className: "w-28",
    },
    {
      key: "title",
      header: "Incident",
      cell: (archive: ArchiveType) => (
        <div className="min-w-0 max-w-xs sm:max-w-sm lg:max-w-md">
          <p className="truncate font-medium">{archive.incident_title || `Archived incident ${archive.incident_id}`}</p>
          <p className="truncate text-xs text-muted-foreground mt-1">
            {archive.fix_detail || archive.fix_status}
          </p>
        </div>
      ),
    },
    {
      key: "source_ips",
      header: "Source IPs",
      cell: (archive: ArchiveType) => {
        let ips: string[] = [];
        if (archive.source_ips) {
          if (typeof archive.source_ips === "string") {
            ips = archive.source_ips.split(",").map((s) => s.trim()).filter(Boolean);
          } else if (Array.isArray(archive.source_ips)) {
            ips = archive.source_ips;
          }
        }
        if (ips.length === 0) return <span className="text-xs text-muted-foreground">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {ips.slice(0, 2).map((ip: string, i: number) => (
              <Badge key={i} variant="outline" className="font-mono text-xs px-1.5 py-0">
                {ip}
              </Badge>
            ))}
            {ips.length > 2 && (
              <Badge variant="secondary" className="text-xs px-1.5 py-0">
                +{ips.length - 2}
              </Badge>
            )}
          </div>
        );
      },
      className: "w-40",
    },
    {
      key: "fix_status",
      header: "Fix Status",
      cell: (archive: ArchiveType) => (
        <FixStatusBadge status={archive.fix_status} />
      ),
      className: "w-36",
    },
    {
      key: "incident",
      header: "Incident ID",
      cell: (archive: ArchiveType) => (
        <Badge
          variant="outline"
          className="cursor-pointer font-mono text-xs hover:bg-accent"
          onClick={(e) => {
            e.stopPropagation();
            router.push(`/incidents/${archive.incident_id}`);
          }}
        >
          {archive.incident_id}
        </Badge>
      ),
      className: "w-32",
    },
    {
      key: "archived",
      header: "Archived",
      cell: (archive: ArchiveType) => {
        const date = archive.archived_at ? new Date(archive.archived_at) : null;
        return (
          <span className="text-sm text-muted-foreground">
            {date && !isNaN(date.getTime())
              ? formatDistanceToNow(date, { addSuffix: true })
              : "—"}
          </span>
        );
      },
      className: "w-32",
    },
    {
      key: "actions",
      header: "",
      cell: (archive: ArchiveType) => (
        <Button
          variant="ghost"
          size="sm"
          onClick={(e) => {
            e.stopPropagation();
            router.push(`/archives/${archive.id}`);
          }}
        >
          View
          <ArrowRight className="ml-1 h-4 w-4" />
        </Button>
      ),
      className: "w-24",
    },
  ];

  return (
    <div className="flex flex-col">
      <PageHeader
        title="Archives"
        description="Completed investigations and remediation history"
        onRefresh={() => mutate()}
        isLoading={isLoading}
        actions={
          <div className="flex items-center gap-2">
            <Select value={fixStatusFilter} onValueChange={setFixStatusFilter}>
              <SelectTrigger className="w-40 max-sm:w-full">
                <Filter className="mr-2 h-4 w-4" />
                <SelectValue placeholder="Filter status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="likely_fixed">Likely Fixed</SelectItem>
                <SelectItem value="not_fixed">Not Fixed</SelectItem>
                <SelectItem value="declined">Declined</SelectItem>
                <SelectItem value="inconclusive">Inconclusive</SelectItem>
                <SelectItem value="unknown">Unknown</SelectItem>
              </SelectContent>
            </Select>
          </div>
        }
      />

      <div className="flex-1 space-y-6 p-6">
        {/* Stats */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Total Archived</p>
                  <p className="text-3xl font-bold">{stats?.total_archived || 0}</p>
                </div>
                <Archive className="h-10 w-10 text-muted-foreground/30" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Success Rate</p>
                  <div className="flex items-center gap-3">
                    <CircularProgress value={successRate} color={successColor} />
                    <div>
                      <p className="text-2xl font-bold">{successRate.toFixed(0)}%</p>
                      <p className="text-xs text-muted-foreground">Fixed / Verified</p>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Likely Fixed</p>
                  <p className="text-3xl font-bold text-emerald-500">
                    {stats?.by_fix_status?.likely_fixed || 0}
                  </p>
                </div>
                <CheckCircle2 className="h-10 w-10 text-emerald-500/30" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Not Fixed</p>
                  <p className="text-3xl font-bold text-destructive">
                    {stats?.by_fix_status?.not_fixed || 0}
                  </p>
                </div>
                <XCircle className="h-10 w-10 text-destructive/30" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Severity Distribution */}
        {stats && (
          <Card>
            <CardContent className="py-4">
              <div className="flex items-center justify-between mb-2">
                <p className="text-sm font-medium">Severity Distribution</p>
                <Shield className="h-4 w-4 text-muted-foreground" />
              </div>
              <SeverityDistributionBar stats={stats} />
            </CardContent>
          </Card>
        )}

        {/* Filters */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search by title or source IP..."
              className="pl-9"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setOffset(0);
              }}
            />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Select value={severityFilter} onValueChange={(v) => { setSeverityFilter(v); setOffset(0); }}>
              <SelectTrigger className="w-36">
                <AlertTriangle className="mr-2 h-4 w-4" />
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>

            <Select value={timeRange} onValueChange={(v) => { setTimeRange(v); setOffset(0); }}>
              <SelectTrigger className="w-40">
                <Clock className="mr-2 h-4 w-4" />
                <SelectValue placeholder="Time range" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Time</SelectItem>
                <SelectItem value="7d">Last 7 Days</SelectItem>
                <SelectItem value="30d">Last 30 Days</SelectItem>
                <SelectItem value="90d">Last 90 Days</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {error ? (
          <ErrorState
            error={error}
            onRetry={() => mutate()}
          />
        ) : (
          <DataTable
            columns={columns}
            data={archives}
            page={currentPage}
            totalPages={totalPages}
            onPageChange={handlePageChange}
            onRowClick={(archive) => router.push(`/archives/${archive.id}`)}
            isLoading={isLoading}
            emptyMessage="No archived investigations"
          />
        )}
      </div>
    </div>
  );
}
