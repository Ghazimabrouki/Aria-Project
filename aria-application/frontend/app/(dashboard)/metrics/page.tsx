"use client";

import { useState, useCallback, useMemo, useEffect } from "react";
import useSWR from "swr";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import {
  Cpu,
  HardDrive,
  MemoryStick,
  Server,
  AlertTriangle,
  Activity,
  Network,
  RefreshCw,
  Folder,
  ChevronDown,
  ChevronRight,
  Info,
} from "lucide-react";
import {
  metricsAPI,
  type MetricsDashboardResponse,
  type MetricsHostDetailResponse,
  type MetricsHistoryResponse,
  type MetricsDiskAnalysisResponse,
  type DiskConsumer,
  type MetricHost,
  type HostProcess,
} from "@/lib/api";
import { useWSSubscription, type WSMessage } from "@/lib/websocket";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { cn } from "@/lib/utils";
import { ErrorBoundary } from "@/components/error-boundary";
import { useSelectedAsset } from "@/lib/asset-context";
import { SelectedAssetBanner, GlobalScopeBanner } from "@/components/selected-asset-banner";

const statusColors = {
  normal: "text-green-500 bg-green-500/10 border-green-500/30",
  warning: "text-yellow-500 bg-yellow-500/10 border-yellow-500/30",
  critical: "text-red-500 bg-red-500/10 border-red-500/30",
};

function bytesToGB(bytes: number | undefined): number {
  if (bytes == null || Number.isNaN(bytes)) return 0;
  return bytes / 1024 / 1024 / 1024;
}

function getDiskInfo(disk: any) {
  if (!disk) return { usedPercent: 0, usedGB: 0, totalGB: 0, fstype: "", disk_path: "/" };
  const usedPercent = disk.used_percent ?? 0;
  let usedGB = disk.used_gb;
  let totalGB =
    typeof disk.used_gb === "number" && typeof disk.free_gb === "number"
      ? disk.used_gb + disk.free_gb
      : undefined;
  if (usedGB == null && disk.used_bytes != null) {
    usedGB = bytesToGB(disk.used_bytes);
  }
  if (totalGB == null && disk.used_bytes != null && disk.free_bytes != null) {
    totalGB = bytesToGB(disk.used_bytes + disk.free_bytes);
  }
  return {
    usedPercent,
    usedGB: usedGB ?? 0,
    totalGB: totalGB ?? 0,
    fstype: disk.fstype || "",
    disk_path: disk.path || "/",
  };
}

const VIRTUAL_FSTYPES = new Set([
  "devtmpfs", "tmpfs", "proc", "sysfs", "nsfs", "cgroup", "cgroup2",
  "overlay", "squashfs", "ramfs", "hugetlbfs", "tracefs", "securityfs",
  "pstore", "bpf", "configfs", "fusectl", "mqueue", "debugfs", "devpts",
  "efivarfs", "rpc_pipefs", "binfmt_misc",
]);

function getPrimaryDisk(diskArray: any[]) {
  if (!Array.isArray(diskArray) || diskArray.length === 0) {
    return getDiskInfo(null);
  }
  // Filter out virtual filesystems
  const physical = diskArray.filter((d) => !VIRTUAL_FSTYPES.has(d?.fstype));
  if (physical.length === 0) {
    // Fall back to first entry if everything is virtual
    return physical[0] ?? getDiskInfo(diskArray[0]);
  }
  // Prefer root partition, otherwise largest total size
  const root = physical.find((d) => (d.disk_path || d.path) === "/");
  if (root) return root;
  const largest = physical.reduce((best, cur) => {
    const bestTotal = best.totalGB ?? 0;
    const curTotal = cur.totalGB ?? 0;
    return curTotal > bestTotal ? cur : best;
  }, physical[0]);
  return largest;
}

function normalizeProcess(proc: any): HostProcess | null {
  if (!proc) return null;
  // Skip aggregate state-count entries that lack process details
  if (
    proc.state != null &&
    proc.count != null &&
    proc.pid == null &&
    proc.name == null &&
    proc.command == null
  ) {
    return null;
  }
  let mem_mb: number | undefined;
  if (proc.mem_mb != null) mem_mb = proc.mem_mb;
  else if (proc.memory_mb != null) mem_mb = proc.memory_mb;
  else if (proc.memory_rss != null) mem_mb = proc.memory_rss / 1024 / 1024;
  return {
    pid: proc.pid ?? 0,
    name: proc.name || proc.command || "Process",
    cpu: proc.cpu_percent ?? proc.cpu ?? 0,
    mem_mb,
    mem_percent: proc.mem_percent ?? undefined,
  };
}

function formatMB(mb: number): string {
  if (mb >= 1024) return `${(mb / 1024).toFixed(2)} GB`;
  return `${mb.toFixed(2)} MB`;
}

function buildCurrentHost(
  dashboardHost: MetricHost | undefined,
  detail: MetricsHostDetailResponse | undefined
) {
  const base = detail || dashboardHost;
  if (!base) return null;

  const dMetrics = dashboardHost?.metrics;
  // The getHost API returns flat fields (cpu, memory, disk, etc.) at the top level.
  // The dashboard API nests them under `metrics`. Normalize both here.
  const dtMetrics = detail?.metrics ?? (detail as any);

  const cpu = {
    current: dtMetrics?.cpu?.usage_percent ?? dMetrics?.cpu?.current ?? 0,
    user: dtMetrics?.cpu?.user_percent ?? dMetrics?.cpu?.user ?? 0,
    system: dtMetrics?.cpu?.system_percent ?? dMetrics?.cpu?.system ?? 0,
    iowait: dtMetrics?.cpu?.iowait_percent ?? dMetrics?.cpu?.iowait ?? 0,
  };

  const memory = {
    current: dtMetrics?.memory?.used_percent ?? dMetrics?.memory?.current ?? 0,
    used_mb: dtMetrics?.memory?.used_mb ?? dMetrics?.memory?.used_mb ?? 0,
    available_mb:
      dtMetrics?.memory?.available_mb ?? dMetrics?.memory?.available_mb ?? 0,
  };

  const rawDisk = Array.isArray(dtMetrics?.disk)
    ? dtMetrics.disk
    : Array.isArray(dMetrics?.disk)
      ? dMetrics.disk
      : [];
  const disk = rawDisk.map(getDiskInfo);

  const network = {
    in_mb: dtMetrics?.network?.in_mb ?? dMetrics?.network?.in_mb ?? 0,
    out_mb: dtMetrics?.network?.out_mb ?? dMetrics?.network?.out_mb ?? 0,
  };

  const load = {
    "1m": dtMetrics?.load?.load_1 ?? dMetrics?.load?.["1m"] ?? 0,
    "5m": dtMetrics?.load?.load_5 ?? dMetrics?.load?.["5m"] ?? 0,
    "15m": dtMetrics?.load?.load_15 ?? dMetrics?.load?.["15m"] ?? 0,
    cpus: dtMetrics?.load?.n_cpus ?? dMetrics?.load?.cpus ?? 0,
  };

  const connections = {
    tcp_established:
      dtMetrics?.connections?.tcp_established ??
      dMetrics?.connections?.tcp_established ??
      0,
    tcp_listen:
      dtMetrics?.connections?.tcp_listen ??
      dMetrics?.connections?.tcp_listen ??
      0,
    udp:
      dtMetrics?.connections?.udp_socket ??
      dMetrics?.connections?.udp ??
      0,
  };

  // Build unified process list from detail array or dashboard top_cpu
  // getHost API returns processes at top level; dashboard nests under processes.top_cpu
  const rawProcs = Array.isArray((detail as any)?.processes)
    ? (detail as any).processes
    : Array.isArray(dashboardHost?.processes?.top_cpu)
      ? dashboardHost.processes.top_cpu
      : [];

  const normalizedProcs = rawProcs
    .map(normalizeProcess)
    .filter((p: HostProcess | null): p is HostProcess => p !== null);

  // Fallback aggregate process states when per-process details aren't available
  const processStates = normalizedProcs.length === 0
    ? rawProcs
        .filter((p: any) => p?.state != null && p?.count != null)
        .map((p: any) => ({ state: String(p.state), count: Number(p.count) }))
    : [];

  const top_cpu = normalizedProcs.slice(0, 10);
  const top_memory = [...normalizedProcs]
    .sort(
      (a, b) =>
        (b.mem_mb ?? b.mem_percent ?? 0) - (a.mem_mb ?? a.mem_percent ?? 0)
    )
    .slice(0, 10);

  return {
    hostname: detail?.hostname || dashboardHost?.hostname || "",
    ip: detail?.ip || dashboardHost?.ip || "",
    status:
      (detail?.alert_status as any) || dashboardHost?.status || "normal",
    metrics: { cpu, memory, disk, network, load, connections },
    processes: { top_cpu, top_memory, process_states: processStates },
    procstat_missing: detail?.procstat_missing ?? false,
  };
}

export default function MetricsPage() {
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState<string>("24");
  const [liveMode, setLiveMode] = useState<boolean>(false);
  const { selectedAssetId } = useSelectedAsset();

  const refreshInterval = liveMode ? 5000 : 30000;
  const historyRefreshInterval = liveMode ? 10000 : 60000;

  const {
    data: dashboard,
    isLoading,
    isValidating: isValidatingDashboard,
    error: dashboardError,
    mutate: mutateDashboard,
  } = useSWR<MetricsDashboardResponse>(
    ["metrics-dashboard", selectedAssetId],
    () => metricsAPI.getDashboard(selectedAssetId),
    { refreshInterval }
  );

  const { data: healthDetailed } = useSWR(
    "metrics-health-detailed",
    () => metricsAPI.getHealthDetailed(),
    { refreshInterval: 60000 }
  );

  const healthIssues = useMemo(() => {
    if (!healthDetailed?.components) return [];
    const issues: { name: string; status: string; message?: string }[] = [];
    for (const [name, comp] of Object.entries(healthDetailed.components)) {
      if (comp.status === "unhealthy" || comp.status === "degraded" || comp.status === "error") {
        issues.push({ name, status: comp.status, message: comp.message });
      }
    }
    return issues;
  }, [healthDetailed]);

  const {
    data: hostDetail,
    isValidating: isValidatingHostDetail,
    mutate: mutateHostDetail,
  } = useSWR<MetricsHostDetailResponse>(
    selectedHost ? ["metrics-host", selectedHost, selectedAssetId] : null,
    () => metricsAPI.getHost(selectedHost!, selectedAssetId),
    { refreshInterval }
  );

  const { data: diskAnalysis, isValidating: isValidatingDiskAnalysis, mutate: mutateDiskAnalysis } = useSWR<MetricsDiskAnalysisResponse>(
    selectedHost ? ["metrics-disk-analysis", selectedHost] : null,
    () => metricsAPI.getHostDiskAnalysis(selectedHost!),
    { refreshInterval: historyRefreshInterval }
  );

  const historyLimit = Math.min(parseInt(timeRange) * 120, 1000);

  const { data: cpuHistory, isValidating: isValidatingCpuHistory, mutate: mutateCpuHistory } =
    useSWR<MetricsHistoryResponse>(
      selectedHost ? ["metrics-history-cpu", selectedHost, timeRange] : null,
      () => metricsAPI.getHostHistory(selectedHost!, { metric: "cpu", limit: historyLimit }),
      { refreshInterval: historyRefreshInterval }
    );

  const { data: memHistory, isValidating: isValidatingMemHistory, mutate: mutateMemHistory } =
    useSWR<MetricsHistoryResponse>(
      selectedHost ? ["metrics-history-memory", selectedHost, timeRange] : null,
      () => metricsAPI.getHostHistory(selectedHost!, { metric: "memory", limit: historyLimit }),
      { refreshInterval: historyRefreshInterval }
    );

  const { data: diskHistory, isValidating: isValidatingDiskHistory, mutate: mutateDiskHistory } =
    useSWR<MetricsHistoryResponse>(
      selectedHost ? ["metrics-history-disk", selectedHost, timeRange] : null,
      () => metricsAPI.getHostHistory(selectedHost!, { metric: "disk", limit: historyLimit }),
      { refreshInterval: historyRefreshInterval }
    );

  const { data: netHistory, isValidating: isValidatingNetHistory, mutate: mutateNetHistory } =
    useSWR<MetricsHistoryResponse>(
      selectedHost ? ["metrics-history-network", selectedHost, timeRange] : null,
      () => metricsAPI.getHostHistory(selectedHost!, { metric: "network", limit: historyLimit }),
      { refreshInterval: historyRefreshInterval }
    );

  const { data: loadHistory, isValidating: isValidatingLoadHistory, mutate: mutateLoadHistory } =
    useSWR<MetricsHistoryResponse>(
      selectedHost ? ["metrics-history-load", selectedHost, timeRange] : null,
      () => metricsAPI.getHostHistory(selectedHost!, { metric: "load", limit: historyLimit }),
      { refreshInterval: historyRefreshInterval }
    );

  const handleWSUpdate = useCallback(
    (message: WSMessage) => {
      mutateDashboard();
      if (selectedHost) {
        mutateHostDetail();
        mutateDiskAnalysis();
        mutateCpuHistory();
        mutateMemHistory();
        mutateDiskHistory();
        mutateNetHistory();
        mutateLoadHistory();
      }
    },
    [
      mutateDashboard,
      mutateHostDetail,
      mutateDiskAnalysis,
      mutateCpuHistory,
      mutateMemHistory,
      mutateDiskHistory,
      mutateNetHistory,
      mutateLoadHistory,
      selectedHost,
    ]
  );

  useWSSubscription("performance_alert", handleWSUpdate);

  const hosts = dashboard?.hosts || [];

  // Auto-select first host when dashboard loads so history hooks fire
  useEffect(() => {
    if (!selectedHost && hosts.length > 0) {
      setSelectedHost(hosts[0].hostname);
    }
  }, [hosts, selectedHost]);

  const dashboardHost = useMemo(() => {
    if (!selectedHost) return hosts[0];
    return hosts.find((h) => h.hostname === selectedHost);
  }, [hosts, selectedHost]);

  const currentHost = buildCurrentHost(dashboardHost, hostDetail);

  const cpuChartData = useMemo(
    () =>
      (cpuHistory?.data_points || []).map((d) => {
        const ts = d.timestamp ? new Date(d.timestamp) : null;
        return {
          time: ts && !isNaN(ts.getTime())
            ? ts.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })
            : "—",
          cpu: d.value,
        };
      }),
    [cpuHistory]
  );

  const memChartData = useMemo(
    () =>
      (memHistory?.data_points || []).map((d) => {
        const ts = d.timestamp ? new Date(d.timestamp) : null;
        return {
          time: ts && !isNaN(ts.getTime())
            ? ts.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })
            : "—",
          memory: d.value,
        };
      }),
    [memHistory]
  );

  const netChartData = useMemo(
    () =>
      (netHistory?.data_points || []).map((d) => {
        const ts = d.timestamp ? new Date(d.timestamp) : null;
        return {
          time: ts && !isNaN(ts.getTime())
            ? ts.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })
            : "—",
          network: (d.value ?? 0) / 1024 / 1024,
        };
      }),
    [netHistory]
  );

  function computeStats(values: number[] | undefined) {
    if (!values || values.length === 0) return null;
    const avg = values.reduce((a, b) => a + b, 0) / values.length;
    return { avg, min: Math.min(...values), max: Math.max(...values) };
  }

  const cpuStats = computeStats(cpuHistory?.data_points.map((d) => d.value));
  const memStats = computeStats(memHistory?.data_points.map((d) => d.value));
  const diskStats = computeStats(diskHistory?.data_points.map((d) => d.value));

  const handleRefresh = () => {
    mutateDashboard(undefined, { revalidate: true });
    if (selectedHost) {
      mutateHostDetail(undefined, { revalidate: true });
      mutateDiskAnalysis(undefined, { revalidate: true });
      mutateCpuHistory(undefined, { revalidate: true });
      mutateMemHistory(undefined, { revalidate: true });
      mutateDiskHistory(undefined, { revalidate: true });
      mutateNetHistory(undefined, { revalidate: true });
      mutateLoadHistory(undefined, { revalidate: true });
    }
  };

  const isValidating =
    isValidatingDashboard ||
    isValidatingHostDetail ||
    isValidatingDiskAnalysis ||
    isValidatingCpuHistory ||
    isValidatingMemHistory ||
    isValidatingDiskHistory ||
    isValidatingNetHistory ||
    isValidatingLoadHistory;

  // Ensure selectValue always matches an existing host to avoid Radix Select crashes
  const validHostnames = hosts.map((h) => h.hostname);
  const selectValue =
    selectedHost && validHostnames.includes(selectedHost)
      ? selectedHost
      : validHostnames[0] || "";

  if (dashboardError) {
    return (
      <div className="flex flex-col">
        <PageHeader
          title="Hardware Resources"
          description="Real-time performance monitoring"
          onRefresh={handleRefresh}
          isLoading={isValidating}
        />
        <div className="flex-1 flex items-center justify-center p-6">
          <Card className="max-w-md w-full">
            <CardContent className="py-12 text-center">
              <p className="text-destructive font-medium">Failed to load metrics</p>
              <p className="text-sm text-muted-foreground mt-1">
                {dashboardError instanceof Error ? dashboardError.message : "Unknown error"}
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  if (!isLoading && hosts.length === 0) {
    return (
      <div className="flex flex-col">
        <PageHeader
          title="Hardware Resources"
          description="Real-time performance monitoring"
          onRefresh={handleRefresh}
          isLoading={isValidating}
        />
        <div className="flex-1 flex flex-col items-center justify-center p-6 gap-4">
          {healthIssues.length > 0 && (
            <Card className="max-w-md w-full border-l-4 border-l-amber-500">
              <CardContent className="py-4">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-amber-500 shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <p className="font-medium text-sm">Performance monitoring degraded</p>
                    <ul className="text-sm text-muted-foreground space-y-0.5">
                      {healthIssues.map((issue) => (
                        <li key={issue.name}>
                          <span className="capitalize">{issue.name}</span>: {issue.message || issue.status}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
          <Card className="max-w-md w-full">
            <CardContent className="py-12 text-center">
              <p className="text-muted-foreground">No hosts available</p>
              {healthIssues.length === 0 && (
                <p className="text-xs text-muted-foreground mt-1">
                  Telegraf data may not be flowing yet.
                </p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <ErrorBoundary>
    <div className="flex flex-col">
      {healthIssues.length > 0 && (
        <div className="mx-6 mt-4">
          <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-amber-600 shrink-0 mt-0.5" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-amber-900">
                Performance monitoring degraded
              </p>
              <p className="text-xs text-amber-700 mt-0.5">
                {healthIssues.map((i) => `${i.name}: ${i.message || i.status}`).join("; ")}
              </p>
            </div>
          </div>
        </div>
      )}
      <div className="mx-6 mt-4 space-y-2">
        <SelectedAssetBanner />
        <GlobalScopeBanner />
      </div>
      <PageHeader
        title="Hardware Resources"
        description="Real-time performance monitoring"
        onRefresh={handleRefresh}
        isLoading={isValidating}
        isLive={liveMode}
        actions={
          <div className="flex items-center gap-2">
            <Select
              value={selectValue}
              onValueChange={(v) => setSelectedHost(v)}
              disabled={hosts.length === 0}
            >
              <SelectTrigger className="w-44 max-sm:w-full">
                <SelectValue placeholder="Select host" />
              </SelectTrigger>
              <SelectContent>
                {hosts.map((host) => (
                  <SelectItem key={host.hostname} value={host.hostname}>
                    <div className="flex items-center gap-2">
                      <span
                        className={cn(
                          "w-2 h-2 rounded-full",
                          host.status === "critical" && "bg-red-500",
                          host.status === "warning" && "bg-yellow-500",
                          host.status === "normal" && "bg-green-500"
                        )}
                      />
                      {host.hostname}
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={timeRange} onValueChange={setTimeRange}>
              <SelectTrigger className="w-32">
                <SelectValue placeholder="Time range" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1">Last 1 hour</SelectItem>
                <SelectItem value="6">Last 6 hours</SelectItem>
                <SelectItem value="24">Last 24 hours</SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant={liveMode ? "default" : "outline"}
              size="sm"
              onClick={() => setLiveMode((v) => !v)}
              className={cn(
                "gap-1.5 text-xs",
                liveMode && "bg-success text-success-foreground hover:bg-success/90"
              )}
            >
              <span className={cn("relative flex h-2 w-2", liveMode && "animate-pulse")}>
                <span className={cn("inline-flex h-full w-full rounded-full", liveMode ? "bg-white" : "bg-muted-foreground")} />
              </span>
              {liveMode ? "Live" : "Realtime"}
            </Button>
          </div>
        }
      />

      <div className="flex-1 space-y-6 p-6">
        {isLoading && !currentHost ? (
          <div className="flex items-center justify-center py-20">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          </div>
        ) : currentHost ? (
          <>
            {/* Host Overview Cards */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <MetricCard
                title="CPU Usage"
                value={currentHost.metrics.cpu.current}
                subtitle={`User: ${currentHost.metrics.cpu.user.toFixed(1)}% | System: ${currentHost.metrics.cpu.system.toFixed(1)}%`}
                icon={Cpu}
                color="chart-1"
              />
              <MetricCard
                title="Memory Usage"
                value={currentHost.metrics.memory.current}
                subtitle={`${currentHost.metrics.memory.used_mb.toLocaleString()} MB used / ${(currentHost.metrics.memory.used_mb + currentHost.metrics.memory.available_mb).toLocaleString()} MB total`}
                icon={MemoryStick}
                color="chart-2"
              />
              <MetricCard
                title="Disk Usage"
                value={getPrimaryDisk(currentHost.metrics.disk).usedPercent || 0}
                subtitle={`${(getPrimaryDisk(currentHost.metrics.disk).usedGB || 0).toFixed(1)} GB used / ${(getPrimaryDisk(currentHost.metrics.disk).totalGB || 0).toFixed(1)} GB total`}
                icon={HardDrive}
                color="chart-3"
              />
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between mb-3">
                    <p className="text-sm text-muted-foreground">Load Average</p>
                    <Activity className="h-5 w-5 text-chart-4" />
                  </div>
                  <div className="flex items-baseline gap-4">
                    <div>
                      <span className="text-2xl font-bold">
                        {currentHost.metrics.load["1m"].toFixed(2)}
                      </span>
                      <span className="text-xs text-muted-foreground ml-1">1m</span>
                    </div>
                    <div>
                      <span className="text-lg">{currentHost.metrics.load["5m"].toFixed(2)}</span>
                      <span className="text-xs text-muted-foreground ml-1">5m</span>
                    </div>
                    <div>
                      <span className="text-lg">
                        {currentHost.metrics.load["15m"].toFixed(2)}
                      </span>
                      <span className="text-xs text-muted-foreground ml-1">15m</span>
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground mt-2">
                    {currentHost.metrics.load.cpus} CPUs
                  </p>
                </CardContent>
              </Card>
            </div>

            {/* Status Alert */}
            {currentHost.status !== "normal" && (
              <Card
                className={cn(
                  "border",
                  currentHost.status === "critical" &&
                    "border-destructive/50 bg-destructive/5",
                  currentHost.status === "warning" &&
                    "border-yellow-500/50 bg-yellow-500/5"
                )}
              >
                <CardContent className="flex items-center gap-3 py-4">
                  <AlertTriangle
                    className={cn(
                      "h-5 w-5",
                      currentHost.status === "critical" && "text-destructive",
                      currentHost.status === "warning" && "text-yellow-500"
                    )}
                  />
                  <div>
                    <p
                      className={cn(
                        "font-medium",
                        currentHost.status === "critical" && "text-destructive",
                        currentHost.status === "warning" && "text-yellow-500"
                      )}
                    >
                      {currentHost.status === "critical" ? "Critical Alert" : "Warning"}
                    </p>
                    <p className="text-sm text-muted-foreground">
                      Host {currentHost.hostname} has elevated resource usage
                    </p>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Tabs for different views */}
            <Tabs defaultValue="overview" className="space-y-4">
              <TabsList>
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="network">Network</TabsTrigger>
                <TabsTrigger value="disk">Disk</TabsTrigger>
                <TabsTrigger value="processes">Processes</TabsTrigger>
              </TabsList>

              <TabsContent value="overview" className="space-y-4">
                {/* Charts */}
                <div className="grid gap-6 lg:grid-cols-2">
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="flex items-center gap-2 text-base font-medium">
                        <Cpu className="h-4 w-4 text-chart-1" />
                        CPU Usage
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="h-[250px] relative">
                        {isValidatingCpuHistory && cpuChartData.length === 0 && (
                          <div className="absolute inset-0 flex items-center justify-center z-10 bg-card/50">
                            <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                          </div>
                        )}
                        {cpuChartData.length > 0 ? (
                          <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={cpuChartData}>
                              <defs>
                                <linearGradient id="cpuGradient" x1="0" y1="0" x2="0" y2="1">
                                  <stop
                                    offset="0%"
                                    stopColor="var(--color-chart-1)"
                                    stopOpacity={0.4}
                                  />
                                  <stop
                                    offset="100%"
                                    stopColor="var(--color-chart-1)"
                                    stopOpacity={0}
                                  />
                                </linearGradient>
                              </defs>
                              <CartesianGrid
                                strokeDasharray="3 3"
                                stroke="var(--color-border)"
                                vertical={false}
                              />
                              <XAxis
                                dataKey="time"
                                stroke="var(--color-muted-foreground)"
                                fontSize={12}
                                tickLine={false}
                                axisLine={false}
                              />
                              <YAxis
                                stroke="var(--color-muted-foreground)"
                                fontSize={12}
                                tickLine={false}
                                axisLine={false}
                                domain={[0, 100]}
                                tickFormatter={(v) => `${v}%`}
                              />
                              <Tooltip
                                contentStyle={{
                                  backgroundColor: "var(--color-popover)",
                                  border: "1px solid var(--color-border)",
                                  borderRadius: "8px",
                                  color: "var(--color-popover-foreground)",
                                }}
                                formatter={(value: number) => [
                                  `${value.toFixed(1)}%`,
                                  "CPU",
                                ]}
                              />
                              <Area
                                type="monotone"
                                dataKey="cpu"
                                stroke="var(--color-chart-1)"
                                strokeWidth={2}
                                fill="url(#cpuGradient)"
                              />
                            </AreaChart>
                          </ResponsiveContainer>
                        ) : (
                          <div className="h-full flex items-center justify-center">
                            <p className="text-muted-foreground">No history data</p>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="flex items-center gap-2 text-base font-medium">
                        <MemoryStick className="h-4 w-4 text-chart-2" />
                        Memory Usage
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="h-[250px] relative">
                        {isValidatingMemHistory && memChartData.length === 0 && (
                          <div className="absolute inset-0 flex items-center justify-center z-10 bg-card/50">
                            <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                          </div>
                        )}
                        {memChartData.length > 0 ? (
                          <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={memChartData}>
                              <defs>
                                <linearGradient id="memGradient" x1="0" y1="0" x2="0" y2="1">
                                  <stop
                                    offset="0%"
                                    stopColor="var(--color-chart-2)"
                                    stopOpacity={0.4}
                                  />
                                  <stop
                                    offset="100%"
                                    stopColor="var(--color-chart-2)"
                                    stopOpacity={0}
                                  />
                                </linearGradient>
                              </defs>
                              <CartesianGrid
                                strokeDasharray="3 3"
                                stroke="var(--color-border)"
                                vertical={false}
                              />
                              <XAxis
                                dataKey="time"
                                stroke="var(--color-muted-foreground)"
                                fontSize={12}
                                tickLine={false}
                                axisLine={false}
                              />
                              <YAxis
                                stroke="var(--color-muted-foreground)"
                                fontSize={12}
                                tickLine={false}
                                axisLine={false}
                                domain={[0, 100]}
                                tickFormatter={(v) => `${v}%`}
                              />
                              <Tooltip
                                contentStyle={{
                                  backgroundColor: "var(--color-popover)",
                                  border: "1px solid var(--color-border)",
                                  borderRadius: "8px",
                                  color: "var(--color-popover-foreground)",
                                }}
                                formatter={(value: number) => [
                                  `${value.toFixed(1)}%`,
                                  "Memory",
                                ]}
                              />
                              <Area
                                type="monotone"
                                dataKey="memory"
                                stroke="var(--color-chart-2)"
                                strokeWidth={2}
                                fill="url(#memGradient)"
                              />
                            </AreaChart>
                          </ResponsiveContainer>
                        ) : (
                          <div className="h-full flex items-center justify-center">
                            <p className="text-muted-foreground">No history data</p>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Statistics */}
                {cpuStats && memStats && diskStats && (
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-base font-medium">
                        Statistics ({timeRange}h)
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid gap-4 md:grid-cols-3">
                        <div className="space-y-2">
                          <p className="text-sm font-medium">CPU</p>
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">Average</span>
                            <span>{cpuStats.avg.toFixed(1)}%</span>
                          </div>
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">Min / Max</span>
                            <span>
                              {cpuStats.min.toFixed(1)}% /{" "}
                              {cpuStats.max.toFixed(1)}%
                            </span>
                          </div>
                        </div>
                        <div className="space-y-2">
                          <p className="text-sm font-medium">Memory</p>
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">Average</span>
                            <span>{memStats.avg.toFixed(1)}%</span>
                          </div>
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">Min / Max</span>
                            <span>
                              {memStats.min.toFixed(1)}% /{" "}
                              {memStats.max.toFixed(1)}%
                            </span>
                          </div>
                        </div>
                        <div className="space-y-2">
                          <p className="text-sm font-medium">Disk</p>
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">Average</span>
                            <span>{diskStats.avg.toFixed(1)}%</span>
                          </div>
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">Min / Max</span>
                            <span>
                              {diskStats.min.toFixed(1)}% /{" "}
                              {diskStats.max.toFixed(1)}%
                            </span>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              <TabsContent value="network" className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                  <Card>
                    <CardContent className="pt-6">
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-sm text-muted-foreground">Network In</p>
                        <Network className="h-4 w-4 text-chart-1" />
                      </div>
                      <p className="text-2xl font-bold">
                        {formatMB(currentHost.metrics.network.in_mb)}
                      </p>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="pt-6">
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-sm text-muted-foreground">Network Out</p>
                        <Network className="h-4 w-4 text-chart-2" />
                      </div>
                      <p className="text-2xl font-bold">
                        {formatMB(currentHost.metrics.network.out_mb)}
                      </p>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="pt-6">
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-sm text-muted-foreground">TCP Established</p>
                      </div>
                      <p className="text-2xl font-bold">
                        {currentHost.metrics.connections.tcp_established}
                      </p>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="pt-6">
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-sm text-muted-foreground">TCP Listen</p>
                      </div>
                      <p className="text-2xl font-bold">
                        {currentHost.metrics.connections.tcp_listen}
                      </p>
                    </CardContent>
                  </Card>
                </div>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-base font-medium">
                      <Network className="h-4 w-4" />
                      Network Traffic
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="h-[250px] relative">
                      {isValidatingNetHistory && netChartData.length === 0 && (
                        <div className="absolute inset-0 flex items-center justify-center z-10 bg-card/50">
                          <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                        </div>
                      )}
                      {netChartData.length > 0 ? (
                        <ResponsiveContainer width="100%" height="100%">
                          <AreaChart data={netChartData}>
                            <defs>
                              <linearGradient id="netInGradient" x1="0" y1="0" x2="0" y2="1">
                                <stop
                                  offset="0%"
                                  stopColor="var(--color-chart-1)"
                                  stopOpacity={0.4}
                                />
                                <stop
                                  offset="100%"
                                  stopColor="var(--color-chart-1)"
                                  stopOpacity={0}
                                />
                              </linearGradient>
                            </defs>
                            <CartesianGrid
                              strokeDasharray="3 3"
                              stroke="var(--color-border)"
                              vertical={false}
                            />
                            <XAxis
                              dataKey="time"
                              stroke="var(--color-muted-foreground)"
                              fontSize={12}
                              tickLine={false}
                              axisLine={false}
                            />
                            <YAxis
                              stroke="var(--color-muted-foreground)"
                              fontSize={12}
                              tickLine={false}
                              axisLine={false}
                              tickFormatter={(v) => `${v.toFixed(1)} MB/s`}
                            />
                            <Tooltip
                              contentStyle={{
                                backgroundColor: "var(--color-popover)",
                                border: "1px solid var(--color-border)",
                                borderRadius: "8px",
                              }}
                              formatter={(value: number) => [
                                `${value.toFixed(2)} MB/s`,
                                "Incoming",
                              ]}
                            />
                            <Area
                              type="monotone"
                              dataKey="network"
                              name="Incoming"
                              stroke="var(--color-chart-1)"
                              strokeWidth={2}
                              fill="url(#netInGradient)"
                            />
                          </AreaChart>
                        </ResponsiveContainer>
                      ) : (
                        <div className="h-full flex items-center justify-center">
                          <p className="text-muted-foreground">No history data</p>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="disk" className="space-y-4">
                {/* Disk Overview Cards */}
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                  {currentHost.metrics.disk
                    .filter((d: any) => d.fstype !== "nsfs")
                    .map((d: any, idx: number) => {
                    const usedPct = d.usedPercent || 0;
                    const isWarning = usedPct > 70;
                    const isCritical = usedPct > 90;
                    return (
                      <Card
                        key={idx}
                        className={cn(
                          isCritical && "border-destructive/50",
                          isWarning && !isCritical && "border-yellow-500/50"
                        )}
                      >
                        <CardContent className="pt-6">
                          <div className="space-y-3">
                            <div className="flex items-center justify-between">
                              <p className="text-sm text-muted-foreground">{d.disk_path || "/"}</p>
                              <HardDrive className={cn("h-5 w-5", isCritical ? "text-destructive" : isWarning ? "text-yellow-500" : "text-chart-3")} />
                            </div>
                            <div className="flex items-baseline gap-2">
                              <p
                                className={cn(
                                  "text-3xl font-bold",
                                  isCritical && "text-destructive",
                                  isWarning && !isCritical && "text-yellow-500"
                                )}
                              >
                                {usedPct.toFixed(1)}%
                              </p>
                            </div>
                            <Progress
                              value={usedPct}
                              className={cn(
                                "h-2",
                                isCritical && "[&>div]:bg-destructive",
                                isWarning && !isCritical && "[&>div]:bg-yellow-500"
                              )}
                            />
                            <p className="text-xs text-muted-foreground">
                              {(d.usedGB || 0).toFixed(1)} GB used / {(d.totalGB || 0).toFixed(1)} GB total
                            </p>
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>

                {/* Disk Detail & Consumers */}
                <div className="grid gap-4 lg:grid-cols-2">
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base font-medium">Disk Breakdown</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {(diskAnalysis?.disk_devices || currentHost.metrics.disk)
                          .filter((d: any) => (d.fstype || "") !== "nsfs")
                          .map((d: any, idx: number) => {
                          const usedPct = d.used_percent ?? d.usedPercent ?? 0;
                          const usedBytes = d.used_bytes ?? d.usedBytes ?? 0;
                          const freeBytes = d.free_bytes ?? d.freeBytes ?? 0;
                          const totalBytes = usedBytes + freeBytes;
                          const inodesPct = d.inodes_used_percent ?? 0;
                          return (
                            <div key={idx} className="flex items-center justify-between p-3 rounded-lg border">
                              <div className="flex items-center gap-3">
                                <HardDrive className="h-4 w-4 text-muted-foreground" />
                                <div>
                                  <p className="font-medium">{d.path || d.disk_path || "/"}</p>
                                  <p className="text-xs text-muted-foreground">{d.device || "unknown"} {d.fstype ? `(${d.fstype})` : ""}</p>
                                </div>
                              </div>
                              <div className="text-right">
                                <p className={cn("font-mono text-sm", usedPct >= 90 && "text-destructive", usedPct >= 70 && usedPct < 90 && "text-yellow-500")}>
                                  {usedPct.toFixed(1)}%
                                </p>
                                <p className="text-xs text-muted-foreground">
                                  {bytesToGB(usedBytes).toFixed(1)} / {bytesToGB(totalBytes).toFixed(1)} GB
                                  {inodesPct ? ` · Inodes ${inodesPct.toFixed(1)}%` : ""}
                                </p>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base font-medium flex items-center gap-2">
                        <Folder className="h-4 w-4" />
                        Top Disk Consumers
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      {diskAnalysis?.disk_consumers && diskAnalysis.disk_consumers.length > 0 ? (
                        <DiskConsumersPanel
                          consumers={diskAnalysis.disk_consumers}
                          diskDevices={diskAnalysis.disk_devices}
                        />
                      ) : diskAnalysis?.disk_heuristics && diskAnalysis.disk_heuristics.length > 0 ? (
                        <div className="space-y-3">
                          <p className="text-sm text-muted-foreground">Likely space consumers for this host:</p>
                          {diskAnalysis.disk_heuristics.map((h, i) => (
                            <div key={i} className="flex items-start gap-3 p-3 rounded-lg border">
                              <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5" />
                              <p className="text-sm">{h}</p>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="text-center py-8">
                          <p className="text-muted-foreground">No disk consumer data available</p>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>

              <TabsContent value="processes" className="space-y-4">
                <div className="grid gap-4 lg:grid-cols-2">
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base font-medium">
                        Top CPU Processes
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {currentHost.processes.top_cpu.length > 0 ? (
                          currentHost.processes.top_cpu.map((proc: any, i: number) => (
                            <div
                              key={`${proc?.pid}-${i}`}
                              className="flex items-center justify-between p-3 rounded-lg border"
                            >
                              <div className="flex items-center gap-3">
                                <Badge variant="outline" className="font-mono">
                                  {proc?.pid || i + 1}
                                </Badge>
                                <span className="font-medium">
                                  {proc?.name || "Process"}
                                </span>
                              </div>
                              <div className="flex items-center gap-4">
                                <div className="text-right">
                                  <p className="text-sm font-medium">
                                    {typeof proc?.cpu === "number"
                                      ? `${proc.cpu.toFixed(1)}%`
                                      : "-"}
                                  </p>
                                  <p className="text-xs text-muted-foreground">CPU</p>
                                </div>
                                {proc?.mem_mb != null && (
                                  <div className="text-right">
                                    <p className="text-sm font-medium">
                                      {`${proc.mem_mb.toFixed(1)} MB`}
                                    </p>
                                    <p className="text-xs text-muted-foreground">Memory</p>
                                  </div>
                                )}
                                {proc?.mem_percent != null && (
                                  <div className="text-right">
                                    <p className="text-sm font-medium">
                                      {`${proc.mem_percent.toFixed(1)}%`}
                                    </p>
                                    <p className="text-xs text-muted-foreground">Mem %</p>
                                  </div>
                                )}
                              </div>
                            </div>
                          ))
                        ) : currentHost.processes.process_states && currentHost.processes.process_states.length > 0 ? (
                          <div className="space-y-2">
                            <p className="text-sm text-muted-foreground mb-2">Per-process details unavailable. Showing aggregate states from Telegraf:</p>
                            {currentHost.processes.process_states.map((s: any, i: number) => (
                              <div key={s.state} className="flex items-center justify-between p-3 rounded-lg border">
                                <span className="font-medium capitalize">{s.state}</span>
                                <Badge variant="secondary">{s.count.toLocaleString()}</Badge>
                              </div>
                            ))}
                          </div>
                        ) : currentHost.procstat_missing ? (
                          <div className="text-center py-8 space-y-2">
                            <AlertTriangle className="mx-auto h-8 w-8 text-warning" />
                            <p className="text-sm font-medium text-muted-foreground">
                              Telegraf <code>inputs.procstat</code> is not reporting per-process data for <strong>{currentHost.hostname}</strong>.
                            </p>
                            <p className="text-xs text-muted-foreground max-w-xs mx-auto">
                              Root cause: missing or too-restrictive Telegraf process collector config.
                            </p>
                            <p className="text-xs text-muted-foreground max-w-xs mx-auto">
                              Fix: enable <code>[[inputs.procstat]]</code> on the target host with a broader pattern (e.g. <code>pattern = ".*"</code>) and restart Telegraf.
                            </p>
                          </div>
                        ) : (
                          <p className="text-muted-foreground text-center py-8">
                            No process data available
                          </p>
                        )}
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base font-medium">
                        Top Memory Processes
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {currentHost.processes.top_memory.length > 0 ? (
                          currentHost.processes.top_memory.map((proc: any, i: number) => (
                            <div
                              key={`${proc?.pid}-${i}`}
                              className="flex items-center justify-between p-3 rounded-lg border"
                            >
                              <div className="flex items-center gap-3">
                                <Badge variant="outline" className="font-mono">
                                  {proc?.pid || i + 1}
                                </Badge>
                                <span className="font-medium">
                                  {proc?.name || "Process"}
                                </span>
                              </div>
                              <div className="flex items-center gap-4">
                                <div className="text-right">
                                  <p className="text-sm font-medium">
                                    {typeof proc?.cpu === "number"
                                      ? `${proc.cpu.toFixed(1)}%`
                                      : "-"}
                                  </p>
                                  <p className="text-xs text-muted-foreground">CPU</p>
                                </div>
                                {proc?.mem_mb != null && (
                                  <div className="text-right">
                                    <p className="text-sm font-medium">
                                      {`${proc.mem_mb.toFixed(1)} MB`}
                                    </p>
                                    <p className="text-xs text-muted-foreground">Memory</p>
                                  </div>
                                )}
                                {proc?.mem_percent != null && (
                                  <div className="text-right">
                                    <p className="text-sm font-medium">
                                      {`${proc.mem_percent.toFixed(1)}%`}
                                    </p>
                                    <p className="text-xs text-muted-foreground">Mem %</p>
                                  </div>
                                )}
                              </div>
                            </div>
                          ))
                        ) : currentHost.processes.process_states && currentHost.processes.process_states.length > 0 ? (
                          <div className="space-y-2">
                            <p className="text-sm text-muted-foreground mb-2">Per-process details unavailable. Showing aggregate states from Telegraf:</p>
                            {currentHost.processes.process_states.map((s: any, i: number) => (
                              <div key={s.state} className="flex items-center justify-between p-3 rounded-lg border">
                                <span className="font-medium capitalize">{s.state}</span>
                                <Badge variant="secondary">{s.count.toLocaleString()}</Badge>
                              </div>
                            ))}
                          </div>
                        ) : currentHost.procstat_missing ? (
                          <div className="text-center py-8 space-y-2">
                            <AlertTriangle className="mx-auto h-8 w-8 text-warning" />
                            <p className="text-sm font-medium text-muted-foreground">
                              Telegraf <code>inputs.procstat</code> is not reporting per-process data for <strong>{currentHost.hostname}</strong>.
                            </p>
                            <p className="text-xs text-muted-foreground max-w-xs mx-auto">
                              Root cause: missing or too-restrictive Telegraf process collector config.
                            </p>
                            <p className="text-xs text-muted-foreground max-w-xs mx-auto">
                              Fix: enable <code>[[inputs.procstat]]</code> on the target host with a broader pattern (e.g. <code>pattern = ".*"</code>) and restart Telegraf.
                            </p>
                          </div>
                        ) : (
                          <p className="text-muted-foreground text-center py-8">
                            No process data available
                          </p>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>
            </Tabs>
          </>
        ) : null}

        {/* All Hosts */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base font-medium">All Hosts</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {hosts.map((host) => {
                const cpu = host.metrics?.cpu?.current ?? 0;
                const mem = host.metrics?.memory?.current ?? 0;
                const diskPct = host.metrics?.disk?.[0]?.used_percent ?? 0;
                return (
                  <div
                    key={host.hostname}
                    className={cn(
                      "flex items-center justify-between rounded-lg border p-4 transition-colors hover:bg-accent/50 cursor-pointer",
                      host.status === "critical" &&
                        "border-destructive/50 bg-destructive/5",
                      host.status === "warning" &&
                        "border-yellow-500/50 bg-yellow-500/5",
                      selectedHost === host.hostname && "ring-2 ring-primary"
                    )}
                    onClick={() => setSelectedHost(host.hostname)}
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className={cn(
                          "w-3 h-3 rounded-full",
                          host.status === "critical" && "bg-red-500",
                          host.status === "warning" && "bg-yellow-500",
                          host.status === "normal" && "bg-green-500"
                        )}
                      />
                      <div>
                        <p className="font-medium">{host.hostname}</p>
                        <p className="text-xs text-muted-foreground font-mono">
                          {host.ip || host.hostname}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-6">
                      <div className="text-right">
                        <p className="text-xs text-muted-foreground">CPU</p>
                        <p className="font-mono text-sm">{cpu.toFixed(1)}%</p>
                      </div>
                      <div className="text-right">
                        <p className="text-xs text-muted-foreground">Memory</p>
                        <p className="font-mono text-sm">{mem.toFixed(1)}%</p>
                      </div>
                      <div className="text-right">
                        <p className="text-xs text-muted-foreground">Disk</p>
                        <p className="font-mono text-sm">{diskPct.toFixed(1)}%</p>
                      </div>
                      <Badge
                        variant="outline"
                        className={cn(
                          statusColors[host.status as keyof typeof statusColors]
                        )}
                      >
                        {host.status}
                      </Badge>
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
    </ErrorBoundary>
  );
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function ConsumerRow({
  consumer,
  isChild,
  parentBytes,
  totalDiskBytes,
  maxConsumerBytes,
  expandedPaths,
  togglePath,
}: {
  consumer: DiskConsumer;
  isChild?: boolean;
  parentBytes?: number;
  totalDiskBytes: number;
  maxConsumerBytes: number;
  expandedPaths: Set<string>;
  togglePath: (path: string) => void;
}) {
  const isExpanded = expandedPaths.has(consumer.path);
  const hasChildren = (consumer.children && consumer.children.length > 0) || consumer.has_children;
  const sizeBytes = consumer.size_bytes || 0;
  const percentOfTotal = totalDiskBytes > 0 ? (sizeBytes / totalDiskBytes) * 100 : 0;
  const percentOfParent = parentBytes && parentBytes > 0 ? (sizeBytes / parentBytes) * 100 : 0;
  const barPercent = isChild
    ? parentBytes && parentBytes > 0
      ? (sizeBytes / parentBytes) * 100
      : 0
    : maxConsumerBytes > 0
      ? (sizeBytes / maxConsumerBytes) * 100
      : 0;

  return (
    <div className={cn(isChild && "ml-6 border-l-2 border-border pl-3")}>
      <div
        className={cn(
          "flex items-center gap-3 p-3 rounded-lg border transition-colors",
          !isChild && "hover:bg-accent/50",
          isChild && "border-dashed"
        )}
      >
        {hasChildren ? (
          <button
            onClick={() => togglePath(consumer.path)}
            className="flex items-center justify-center w-5 h-5 rounded hover:bg-accent shrink-0"
            aria-label={isExpanded ? "Collapse" : "Expand"}
          >
            {isExpanded ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
          </button>
        ) : (
          <span className="w-5 shrink-0" />
        )}

        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <span
              className={cn(
                "font-mono truncate",
                isChild ? "text-xs text-muted-foreground" : "text-sm font-medium"
              )}
              title={consumer.path}
            >
              {consumer.path}
            </span>
            <div className="flex items-center gap-2 shrink-0">
              <span className="text-xs text-muted-foreground tabular-nums">
                {isChild
                  ? percentOfParent > 0
                    ? `${percentOfParent.toFixed(1)}% of parent`
                    : ""
                  : percentOfTotal > 0
                    ? `${percentOfTotal.toFixed(1)}% of disk`
                    : ""}
              </span>
              <Badge variant="secondary" className="text-xs tabular-nums">
                {consumer.size_human}
              </Badge>
            </div>
          </div>
          <div className="mt-1.5 h-1.5 w-full rounded-full bg-secondary overflow-hidden">
            <div
              className={cn(
                "h-full rounded-full transition-all",
                isChild ? "bg-chart-3/60" : "bg-chart-3"
              )}
              style={{ width: `${Math.min(barPercent, 100)}%` }}
            />
          </div>
        </div>
      </div>

      {isExpanded && consumer.children && consumer.children.length > 0 && (
        <div className="mt-1 space-y-1">
          {consumer.children.map((child, idx) => (
            <ConsumerRow
              key={`${child.path}-${idx}`}
              consumer={child}
              isChild
              parentBytes={sizeBytes}
              totalDiskBytes={totalDiskBytes}
              maxConsumerBytes={maxConsumerBytes}
              expandedPaths={expandedPaths}
              togglePath={togglePath}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function DiskConsumersPanel({
  consumers,
  diskDevices,
}: {
  consumers: DiskConsumer[];
  diskDevices: MetricsDiskAnalysisResponse["disk_devices"];
}) {
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set());

  const totalDiskBytes = useMemo(() => {
    const rootDevice = diskDevices.find((d) => d.path === "/" || d.path === "");
    if (rootDevice?.used_bytes) return rootDevice.used_bytes;
    // Fallback: sum of all device used_bytes
    return diskDevices.reduce((sum, d) => sum + (d.used_bytes || 0), 0);
  }, [diskDevices]);

  const totalDiskGB = totalDiskBytes / 1024 / 1024 / 1024;

  const accountedBytes = useMemo(() => {
    return consumers.reduce((sum, c) => sum + (c.size_bytes || 0), 0);
  }, [consumers]);

  const accountedGB = accountedBytes / 1024 / 1024 / 1024;
  const accountedPercent = totalDiskBytes > 0 ? (accountedBytes / totalDiskBytes) * 100 : 0;
  const unaccountedGB = Math.max(0, totalDiskGB - accountedGB);

  const maxConsumerBytes = useMemo(() => {
    return Math.max(...consumers.map((c) => c.size_bytes || 0), 1);
  }, [consumers]);

  const togglePath = useCallback((path: string) => {
    setExpandedPaths((prev) => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  }, []);

  return (
    <div className="space-y-4">
      {/* Header banner */}
      <div className="flex items-start gap-2 rounded-md bg-muted/50 p-3">
        <Info className="h-4 w-4 text-muted-foreground mt-0.5 shrink-0" />
        <div className="space-y-1">
          <p className="text-sm font-medium">Top-Level Directory Usage</p>
          <p className="text-xs text-muted-foreground">
            Directory sizes reported by <code className="text-xs bg-muted px-1 rounded">du</code>. This list covers major top-level directories only — it does not include Docker images, container layers, package caches, logs, or files stored directly under <code>/</code>. The sum of visible directories will usually be significantly less than total disk usage.
          </p>
        </div>
      </div>

      {/* Transparency summary */}
      {totalDiskBytes > 0 && accountedBytes > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Accounted space</span>
            <span className="tabular-nums">
              {accountedGB.toFixed(1)} GB ({accountedPercent.toFixed(1)}%)
            </span>
          </div>
          <div className="h-2 w-full rounded-full bg-secondary overflow-hidden">
            <div
              className="h-full rounded-full bg-chart-3 transition-all"
              style={{ width: `${Math.min(accountedPercent, 100)}%` }}
            />
          </div>
          {unaccountedGB > 0.1 && (
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">Unaccounted / other</span>
              <span className="tabular-nums text-muted-foreground">
                {unaccountedGB.toFixed(1)} GB ({(100 - accountedPercent).toFixed(1)}%)
              </span>
            </div>
          )}
        </div>
      )}

      {/* Directory list */}
      <div className="max-h-[400px] overflow-y-auto space-y-2 pr-1">
        {consumers.map((consumer, i) => (
          <ConsumerRow
            key={`${consumer.path}-${i}`}
            consumer={consumer}
            totalDiskBytes={totalDiskBytes}
            maxConsumerBytes={maxConsumerBytes}
            expandedPaths={expandedPaths}
            togglePath={togglePath}
          />
        ))}
      </div>

      {/* Footer disclaimer */}
      <div className="rounded-md border border-yellow-500/20 bg-yellow-500/5 p-3">
        <div className="flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5 shrink-0" />
          <div className="space-y-1">
            <p className="text-xs font-medium text-yellow-600 dark:text-yellow-400">
              Why the total is larger than the sum shown
            </p>
            <ul className="text-xs text-muted-foreground space-y-0.5 list-disc list-inside">
              <li>Only major top-level directories are scanned — many sub-paths (Docker layers, package caches, build artifacts) are not listed individually</li>
              <li>Files placed directly in <code>/</code> (not inside any subdirectory) are not shown</li>
              <li>Hidden directories, mount points, and overlay filesystems (e.g. snap packages) may not be fully captured</li>
              <li>Container images, VM disks, and swap files often live under paths that appear smaller in top-level summaries</li>
              <li>Reserved filesystem blocks and journal space are counted in total usage but not in directory sizes</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

function MetricCard({
  title,
  value,
  subtitle,
  icon: Icon,
  color,
}: {
  title: string;
  value: number;
  subtitle: string;
  icon: React.ElementType;
  color: string;
}) {
  const isWarning = value > 70;
  const isCritical = value > 90;

  return (
    <Card
      className={cn(
        isCritical && "border-destructive/50",
        isWarning && !isCritical && "border-yellow-500/50"
      )}
    >
      <CardContent className="pt-6">
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">{title}</p>
            <Icon className={cn("h-5 w-5", `text-${color}`)} />
          </div>
          <div className="flex items-baseline gap-2">
            <p
              className={cn(
                "text-3xl font-bold",
                isCritical && "text-destructive",
                isWarning && !isCritical && "text-yellow-500"
              )}
            >
              {value.toFixed(1)}%
            </p>
          </div>
          <Progress
            value={value}
            className={cn(
              "h-2",
              isCritical && "[&>div]:bg-destructive",
              isWarning && !isCritical && "[&>div]:bg-yellow-500"
            )}
          />
          <p className="text-xs text-muted-foreground">{subtitle}</p>
        </div>
      </CardContent>
    </Card>
  );
}
