"use client";

import { useState, useCallback, useMemo } from "react";
import useSWR, { useSWRConfig } from "swr";
import { useRouter } from "next/navigation";
import { formatAbsoluteDateTime, getEventTimestamp } from "@/lib/time";
import { TimeFilter, timePresetToRange, type TimePreset } from "@/components/time-filter";
import {
  ShieldCheck,
  AlertTriangle,
  Activity,
  CheckCircle2,
  Clock,
  Server,
  Terminal,
  FileWarning,
  Search,
  ArrowRight,
  HardDrive,
  Eye as EyeIcon,
  RefreshCw,
  Info,
} from "lucide-react";
import { runtimeAPI } from "@/lib/api";
import { useWSSubscription } from "@/lib/websocket";
import { useSelectedAsset } from "@/lib/asset-context";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { statusClasses, severityClasses } from "@/lib/ui-status";

const statusOptions = [
  { value: "all", label: "All Statuses" },
  { value: "diagnosing", label: "Diagnosing" },
  { value: "findings_ready", label: "Findings Ready" },
  { value: "observe", label: "Observe" },
  { value: "manual_review_required", label: "Manual Review" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "awaiting_approval", label: "Awaiting Approval" },
  { value: "approved", label: "Approved" },
  { value: "running", label: "Running" },
  { value: "verified", label: "Verified" },
  { value: "not_fixed", label: "Not Fixed" },
  { value: "inconclusive", label: "Inconclusive" },
  { value: "remediation_failed", label: "Remediation Failed" },
  { value: "declined", label: "Declined" },
  { value: "archived_fixed", label: "Archived Fixed" },
  { value: "archived_not_fixed", label: "Archived With Risk" },
  { value: "closed_with_risk", label: "Closed With Risk" },
];

const severityOptions = [
  { value: "all", label: "All Severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "info", label: "Info" },
];

const categoryOptions = [
  { value: "all", label: "All Categories" },
  { value: "process_execution", label: "Process Execution" },
  { value: "file_access", label: "File Access" },
  { value: "privilege_escalation", label: "Privilege Escalation" },
  { value: "persistence", label: "Persistence" },
  { value: "service_change", label: "Service Change" },
  { value: "package_manager", label: "Package Manager" },
  { value: "credential_access", label: "Credential Access" },
  { value: "container_runtime", label: "Container Runtime" },
  { value: "network_behavior", label: "Network Behavior" },
];

const decisionOptions = [
  { value: "all", label: "All Decisions" },
  { value: "no_action_expected_activity", label: "Expected Activity" },
  { value: "observe", label: "Observe" },
  { value: "manual_review_required", label: "Manual Review" },
  { value: "evidence_only", label: "Evidence Only" },
  { value: "safe_corrective_action_available", label: "Safe Fix Available" },
  { value: "high_risk_action_requires_approval", label: "Approval Required" },
  { value: "cannot_remediate_missing_context", label: "Missing Context" },
  { value: "remediation_not_supported_for_category", label: "Unsupported" },
];

const STATUS_ICON: Record<string, React.ReactNode> = {
  diagnosing: <Activity className="h-4 w-4 text-amber-400" />,
  findings_ready: <AlertTriangle className="h-4 w-4 text-amber-500" />,
  observe: <EyeIcon className="h-4 w-4 text-blue-500" />,
  manual_review_required: <FileWarning className="h-4 w-4 text-amber-500" />,
  acknowledged: <CheckCircle2 className="h-4 w-4 text-emerald-500" />,
  escalated: <FileWarning className="h-4 w-4 text-rose-500" />,
  awaiting_approval: <Clock className="h-4 w-4 text-blue-400" />,
  approved: <ShieldCheck className="h-4 w-4 text-blue-500" />,
  running: <Activity className="h-4 w-4 text-amber-400 animate-pulse" />,
  completed: <CheckCircle2 className="h-4 w-4 text-emerald-500" />,
  verified: <ShieldCheck className="h-4 w-4 text-emerald-600" />,
  failed: <AlertTriangle className="h-4 w-4 text-destructive" />,
  not_fixed: <AlertTriangle className="h-4 w-4 text-destructive" />,
  inconclusive: <Clock className="h-4 w-4 text-amber-500" />,
  remediation_failed: <AlertTriangle className="h-4 w-4 text-destructive" />,
  declined: <AlertTriangle className="h-4 w-4 text-muted-foreground" />,
  archived_fixed: <HardDrive className="h-4 w-4 text-emerald-500" />,
  archived_not_fixed: <HardDrive className="h-4 w-4 text-amber-500" />,
  closed_with_risk: <HardDrive className="h-4 w-4 text-amber-500" />,
};

// Status & severity colors come from the shared design-token scale
// (lib/ui-status) so they stay consistent with badges across the app.

const CATEGORY_ICON: Record<string, React.ReactNode> = {
  process_execution: <Terminal className="h-3.5 w-3.5" />,
  file_access: <HardDrive className="h-3.5 w-3.5" />,
  privilege_escalation: <ShieldCheck className="h-3.5 w-3.5" />,
  persistence: <Clock className="h-3.5 w-3.5" />,
  service_change: <Server className="h-3.5 w-3.5" />,
  package_manager: <CheckCircle2 className="h-3.5 w-3.5" />,
  credential_access: <AlertTriangle className="h-3.5 w-3.5" />,
  container_runtime: <Server className="h-3.5 w-3.5" />,
  network_behavior: <Activity className="h-3.5 w-3.5" />,
};

const STATS_REFRESH_MS = 15000;
const STATS_KEY = "runtime-stats";

export default function RuntimeInvestigationsPage() {
  const router = useRouter();
  const { mutate: globalMutate } = useSWRConfig();
  const { selectedAssetId } = useSelectedAsset();
  const [offset, setOffset] = useState(0);
  const [status, setStatus] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [category, setCategory] = useState("all");
  const [decision, setDecision] = useState("all");
  const [hostFilter, setHostFilter] = useState("");
  const [containerFilter, setContainerFilter] = useState("");
  const [timePreset, setTimePreset] = useState<TimePreset>("all");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const {
    data: stats,
    mutate: mutateStats,
    isLoading: statsLoading,
  } = useSWR(STATS_KEY, () => runtimeAPI.getStats(), {
    refreshInterval: STATS_REFRESH_MS,
    onSuccess: () => setLastUpdated(new Date()),
  });

  const timeRange = useMemo(() => timePresetToRange(timePreset), [timePreset]);

  const { data, mutate, isLoading, error: listError } = useSWR(
    ["runtime-investigations", offset, status, severity, category, decision, hostFilter, containerFilter, timePreset, selectedAssetId],
    () =>
      runtimeAPI.list({
        limit: 25,
        offset,
        status: status === "all" ? undefined : status,
        severity: severity === "all" ? undefined : severity,
        resource_type: category === "all" ? undefined : category,
        decision: decision === "all" ? undefined : decision,
        host: hostFilter || undefined,
        container: containerFilter || undefined,
        asset_id: selectedAssetId || undefined,
        ...timeRange,
      }),
    { refreshInterval: STATS_REFRESH_MS }
  );

  useWSSubscription("investigation_updated", () => {
    mutate();
    globalMutate(STATS_KEY);
  });

  const handleManualRefresh = useCallback(() => {
    mutateStats();
    mutate();
    setLastUpdated(new Date());
  }, [mutateStats, mutate]);

  const investigations = data?.investigations || [];
  const total = data?.total || 0;

  const bs = stats?.by_status || {};
  const observedCount = bs.observe || 0;
  const awaitingApprovalCount = bs.awaiting_approval || 0;
  const failedRemediationCount =
    (bs.not_fixed || 0) + (bs.remediation_failed || 0) + (bs.verification_failed || 0);

  return (
    <TooltipProvider>
      <div className="space-y-6 p-6">
        <div className="flex items-center justify-between">
          <PageHeader
            title="Runtime Security"
            description="Falco runtime security events and investigations"
            icon={ShieldCheck}
          />
          <div className="flex items-center gap-3">
            {lastUpdated && (
              <span className="text-xs text-muted-foreground">
                Last updated {formatAbsoluteDateTime(lastUpdated)}
              </span>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={handleManualRefresh}
              disabled={statsLoading && !stats}
              className="gap-1.5"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", statsLoading && !stats && "animate-spin")} />
              Refresh
            </Button>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-8 gap-3">
          <StatCard
            label="Total"
            value={stats?.total || 0}
            icon={<Activity className="h-4 w-4" />}
            tooltip="Total runtime investigations in the system."
            testId="stat-total"
          />
          <StatCard
            label="Findings Ready"
            value={bs.findings_ready || 0}
            icon={<AlertTriangle className="h-4 w-4 text-amber-500" />}
            color="amber"
            tooltip="Investigations with diagnostic findings ready for review."
            testId="stat-findings-ready"
          />
          {observedCount > 0 && (
            <StatCard
              label="Observed"
              value={observedCount}
              icon={<EyeIcon className="h-4 w-4 text-blue-500" />}
              color="blue"
              tooltip="Events monitored with no immediate threat identified."
              testId="stat-observed"
            />
          )}
          <StatCard
            label="Manual Review"
            value={bs.manual_review_required || 0}
            icon={<FileWarning className="h-4 w-4 text-amber-500" />}
            color="amber"
            tooltip="Cases requiring analyst review before any action."
            testId="stat-manual-review"
          />
          <StatCard
            label="Acknowledged"
            value={bs.acknowledged || 0}
            icon={<CheckCircle2 className="h-4 w-4 text-emerald-500" />}
            color="emerald"
            tooltip="Investigations acknowledged by an analyst."
            testId="stat-acknowledged"
          />
          {awaitingApprovalCount > 0 && (
            <StatCard
              label="Awaiting Approval"
              value={awaitingApprovalCount}
              icon={<Clock className="h-4 w-4 text-blue-400" />}
              color="blue"
              tooltip="Remediation playbooks generated and waiting for approval."
              testId="stat-awaiting-approval"
            />
          )}
          <StatCard
            label="Verified Fixes"
            value={bs.verified || 0}
            icon={<ShieldCheck className="h-4 w-4 text-emerald-600" />}
            color="emerald"
            tooltip="Cases where corrective remediation was executed and verified as fixed. Does not include unverified 'fixed' states."
            testId="stat-verified-fixes"
          />
          {failedRemediationCount > 0 && (
            <StatCard
              label="Failed Remediations"
              value={failedRemediationCount}
              icon={<AlertTriangle className="h-4 w-4 text-destructive" />}
              color="red"
              tooltip="Cases where remediation execution or post-remediation verification failed."
              testId="stat-failed-remediations"
            />
          )}
          {(bs.declined || 0) > 0 && (
            <StatCard
              label="Declined"
              value={bs.declined || 0}
              icon={<AlertTriangle className="h-4 w-4 text-muted-foreground" />}
              color="neutral"
              tooltip="Remediation proposals explicitly declined by an analyst."
              testId="stat-declined"
            />
          )}
          {(bs.archived_fixed || 0) > 0 && (
            <StatCard
              label="Archived Fixed"
              value={bs.archived_fixed || 0}
              icon={<HardDrive className="h-4 w-4 text-emerald-500" />}
              color="emerald"
              tooltip="Investigations archived after verified remediation."
              testId="stat-archived-fixed"
            />
          )}
          {(bs.archived_not_fixed || 0) > 0 && (
            <StatCard
              label="Archived With Risk"
              value={bs.archived_not_fixed || 0}
              icon={<HardDrive className="h-4 w-4 text-amber-500" />}
              color="amber"
              tooltip="Investigations archived with unresolved risk."
              testId="stat-archived-with-risk"
            />
          )}
          {(bs.closed_with_risk || 0) > 0 && (
            <StatCard
              label="Closed With Risk"
              value={bs.closed_with_risk || 0}
              icon={<AlertTriangle className="h-4 w-4 text-amber-500" />}
              color="amber"
              tooltip="Investigations closed without fixing the underlying risk."
              testId="stat-closed-with-risk"
            />
          )}
          {(() => {
            const explicit =
              (bs.findings_ready || 0) +
              (bs.observe || 0) +
              (bs.manual_review_required || 0) +
              (bs.acknowledged || 0) +
              (bs.awaiting_approval || 0) +
              (bs.verified || 0) +
              failedRemediationCount +
              (bs.declined || 0) +
              (bs.archived_fixed || 0) +
              (bs.archived_not_fixed || 0) +
              (bs.closed_with_risk || 0);
            const other = (stats?.total || 0) - explicit;
            if (other <= 0) return null;
            return (
              <StatCard
                label="Other"
                value={other}
                icon={<Info className="h-4 w-4 text-slate-500" />}
                color="slate"
                tooltip={`Statuses not shown above (e.g., diagnosing, approved, executing, running, inconclusive, fixed). Count: ${other}.`}
                testId="stat-other"
              />
            );
          })()}
        </div>

        {/* Filters */}
        <Card>
          <CardContent className="p-4">
            <div className="flex flex-wrap gap-3">
              <Select value={status} onValueChange={setStatus}>
                <SelectTrigger className="w-[180px] max-sm:w-full">
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  {statusOptions.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger className="w-[160px] max-sm:w-full">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  {severityOptions.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select value={category} onValueChange={setCategory}>
                <SelectTrigger className="w-[180px] max-sm:w-full">
                  <SelectValue placeholder="Category" />
                </SelectTrigger>
                <SelectContent>
                  {categoryOptions.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select value={decision} onValueChange={setDecision}>
                <SelectTrigger className="w-[200px] max-sm:w-full">
                  <SelectValue placeholder="Decision" />
                </SelectTrigger>
                <SelectContent>
                  {decisionOptions.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Filter by host..."
                  value={hostFilter}
                  onChange={(e) => setHostFilter(e.target.value)}
                  className="pl-9"
                />
              </div>

              <div className="relative flex-1 min-w-[200px]">
                <Server className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Filter by container..."
                  value={containerFilter}
                  onChange={(e) => setContainerFilter(e.target.value)}
                  className="pl-9"
                />
              </div>
              <TimeFilter
                value={timePreset}
                onChange={(v) => {
                  setTimePreset(v);
                  setOffset(0);
                }}
              />
            </div>
          </CardContent>
        </Card>

        {/* Investigations Table */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Terminal className="h-4 w-4 text-primary" />
              Runtime Investigations
              <Badge variant="outline" className="ml-2">
                {total}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {isLoading ? (
              <div className="p-6 space-y-3">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div key={i} className="flex items-center gap-4 rounded-lg border p-4">
                    <div className="h-10 w-10 rounded-full bg-muted" />
                    <div className="flex-1 space-y-2">
                      <div className="h-4 w-1/3 bg-muted rounded" />
                      <div className="h-3 w-1/4 bg-muted rounded" />
                    </div>
                    <div className="h-8 w-20 bg-muted rounded" />
                  </div>
                ))}
              </div>
            ) : listError ? (
              <div className="p-8 text-center text-destructive">
                <AlertTriangle className="h-8 w-8 mx-auto mb-2" />
                <div className="font-medium">Failed to load investigations</div>
                <div className="text-sm text-muted-foreground mt-1">
                  {listError instanceof Error ? listError.message : "Please check the backend connection and try again."}
                </div>
                <Button variant="outline" size="sm" className="mt-3" onClick={() => mutate()}>
                  Retry
                </Button>
              </div>
            ) : investigations.length === 0 ? (
              <div className="p-8 text-center text-muted-foreground">
                <ShieldCheck className="h-8 w-8 mx-auto mb-2 text-muted-foreground/50" />
                <div className="font-medium">No runtime investigations found</div>
                {selectedAssetId && (
                  <div className="text-sm text-muted-foreground mt-2 max-w-md mx-auto">
                    <p>No Falco/runtime security events have been mapped to <strong>{selectedAssetId}</strong> yet.</p>
                    <p className="mt-1">Check that Falco is installed and running on this server, and that events are being indexed.</p>
                    <a href="/settings/assets" className="text-primary hover:underline mt-2 inline-block">Review source configuration →</a>
                  </div>
                )}
              </div>
            ) : (
              <div className="divide-y divide-border">
                {investigations.map((inv) => (
                  <div
                    key={inv.id}
                    className="flex items-center gap-4 p-4 hover:bg-accent/50 cursor-pointer transition-colors"
                    onClick={() => router.push(`/runtime/investigations/${inv.id}`)}
                  >
                    <div className="shrink-0">
                      {STATUS_ICON[inv.status] || <Activity className="h-4 w-4" />}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-medium text-sm truncate">
                          {inv.incident_title}
                        </span>
                        <Badge
                          variant="outline"
                          className={cn(
                            "text-xs px-1.5 py-0 h-5",
                            statusClasses(inv.status)
                          )}
                        >
                          {inv.status.replace(/_/g, " ")}
                        </Badge>
                        <Badge
                          variant="outline"
                          className={cn(
                            "text-xs px-1.5 py-0 h-5",
                            severityClasses(inv.incident_severity)
                          )}
                        >
                          {inv.incident_severity}
                        </Badge>
                        {(inv.occurrence_count || 0) > 1 && (
                          <Badge variant="secondary" className="text-xs px-1.5 py-0 h-5">
                            {inv.occurrence_count} occurrences
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-3 text-xs text-muted-foreground">
                        {inv.resource_type && (
                          <span className="flex items-center gap-1">
                            {CATEGORY_ICON[inv.resource_type] || <Terminal className="h-3 w-3" />}
                            {inv.resource_type.replace(/_/g, " ")}
                          </span>
                        )}
                        {inv.rule_name && <span>Rule: {inv.rule_name}</span>}
                        {inv.proc_name && <span>Process: {inv.proc_name}</span>}
                        {inv.decision && <span>Decision: {inv.decision.replace(/_/g, " ")}</span>}
                        {inv.container && <span>Container: {inv.container}</span>}
                        {inv.target_host && (
                          <span className="flex items-center gap-1">
                            <Server className="h-3 w-3" />
                            {inv.target_host}
                          </span>
                        )}
                        <span>
                          Last seen {formatAbsoluteDateTime(getEventTimestamp(inv, "runtime"))}
                        </span>
                      </div>
                    </div>

                    <ArrowRight className="h-4 w-4 text-muted-foreground shrink-0" />
                  </div>
                ))}
              </div>
            )}

            {/* Pagination */}
            {total > 25 && (
              <div className="flex items-center justify-between p-4 border-t">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - 25))}
                >
                  Previous
                </Button>
                <span className="text-sm text-muted-foreground">
                  {offset + 1} - {Math.min(offset + 25, total)} of {total}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={offset + 25 >= total}
                  onClick={() => setOffset(offset + 25)}
                >
                  Next
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </TooltipProvider>
  );
}

function StatCard({
  label,
  value,
  icon,
  color,
  tooltip,
  testId,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
  color?: string;
  tooltip?: string;
  testId?: string;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Card data-testid={testId} className={cn("border cursor-help", color && `border-${color}-500/20`)}>
          <CardContent className="p-3">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-muted-foreground">{label}</span>
              {icon}
            </div>
            <div className="text-2xl font-bold">{value}</div>
          </CardContent>
        </Card>
      </TooltipTrigger>
      {tooltip && (
        <TooltipContent side="bottom" className="max-w-xs">
          <div className="flex items-start gap-2">
            <Info className="h-4 w-4 mt-0.5 shrink-0" />
            <p className="text-sm">{tooltip}</p>
          </div>
        </TooltipContent>
      )}
    </Tooltip>
  );
}
