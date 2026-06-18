"use client";
import { ListPageSkeleton } from "@/components/page-skeletons";

import { useState, useCallback, useMemo, Suspense } from "react";
import useSWR from "swr";
import { useRouter, useSearchParams } from "next/navigation";
import { formatAbsoluteDateTime, getEventTimestamp } from "@/lib/time";
import { TimeFilter, timePresetToRange, type TimePreset } from "@/components/time-filter";
import { X, AlertTriangle, FileWarning, ArrowRight, Tag, Play } from "lucide-react";
import { incidentsAPI, investigationsAPI, type Incident, type IncidentListResponse } from "@/lib/api";
import { useWSSubscription, type WSMessage } from "@/lib/websocket";
import { useSelectedAsset } from "@/lib/asset-context";
import { PageHeader } from "@/components/page-header";
import { DataTable } from "@/components/data-table";
import { ErrorState } from "@/components/error-state";
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
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";

const statusOptions = [
  { value: "all", label: "All Statuses" },
  { value: "open", label: "Open" },
  { value: "investigating", label: "Investigating" },
  { value: "resolved", label: "Resolved" },
  { value: "archived", label: "Archived" },
];

const severityOptions = [
  { value: "all", label: "All Severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

function IncidentsPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { selectedAssetId } = useSelectedAsset();
  const [offset, setOffset] = useState(0);
  const [status, setStatus] = useState(searchParams.get("status") || "all");
  const [severity, setSeverity] = useState(searchParams.get("severity") || "all");
  const [whitelisted, setWhitelisted] = useState(searchParams.get("whitelisted") || "all");
  const [timePreset, setTimePreset] = useState<TimePreset>((searchParams.get("time_preset") as TimePreset) || "all");
  const [launchDialogOpen, setLaunchDialogOpen] = useState(false);
  const [launchIncident, setLaunchIncident] = useState<Incident | null>(null);
  const [launchTargetHost, setLaunchTargetHost] = useState("");
  const [launchTargetUser, setLaunchTargetUser] = useState("root");
  const [launchLoading, setLaunchLoading] = useState(false);
  const { toast } = useToast();
  const limit = 20;

  const timeRange = useMemo(() => timePresetToRange(timePreset), [timePreset]);

  const { data, error, isLoading, mutate } = useSWR<IncidentListResponse>(
    ["incidents", offset, status, severity, whitelisted, timePreset, selectedAssetId],
    () =>
      incidentsAPI.list({
        limit,
        offset,
        status: status !== "all" ? status : undefined,
        severity: severity !== "all" ? severity : undefined,
        whitelisted: whitelisted !== "all" ? whitelisted === "true" : undefined,
        asset_id: selectedAssetId || undefined,
        ...timeRange,
      }),
    { refreshInterval: 30000 }
  );

  const handleWSUpdate = useCallback((message: WSMessage) => {
    mutate();
  }, [mutate]);

  // Subscribe to investigation updates as a proxy for incident-related activity
  useWSSubscription("investigation_updated", handleWSUpdate);
  // Also listen for newly created incidents to refresh the list
  useWSSubscription("incident_created", handleWSUpdate);

  const incidents = data?.incidents || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  const handlePageChange = (page: number) => {
    setOffset((page - 1) * limit);
  };

  const columns = [
    {
      key: "severity",
      header: "Severity",
      cell: (incident: Incident) => <SeverityBadge severity={incident.severity} />,
      className: "w-28",
    },
    {
      key: "title",
      header: "Incident",
      cell: (incident: Incident) => (
        <div className="max-w-lg">
          <div className="flex items-center gap-2">
            <p className="truncate font-medium">{incident.title}</p>
            {incident.whitelisted && <WhitelistBadge whitelisted={incident.whitelisted} />}
          </div>
          <div className="flex items-center gap-2 mt-1 flex-wrap">
            {incident.tags?.slice(0, 2).map((tag, index) => (
              <Badge key={index} variant="secondary" className="text-xs">
                <Tag className="mr-1 h-2 w-2" />
                {tag}
              </Badge>
            ))}
            {incident.tags && incident.tags.length > 2 && (
              <span className="text-xs text-muted-foreground">
                +{incident.tags.length - 2}
              </span>
            )}
          </div>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      cell: (incident: Incident) => <StatusBadge status={incident.status} />,
      className: "w-28",
    },
    {
      key: "alerts",
      header: "Alerts",
      cell: (incident: Incident) => (
        <div className="flex items-center gap-1.5">
          <AlertTriangle className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-sm">{incident.alert_count}</span>
        </div>
      ),
      className: "w-20",
    },

    {
      key: "created",
      header: "Created",
      cell: (incident: Incident) => {
        const ts = getEventTimestamp(incident, "incident");
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
      cell: (incident: Incident) => (
        <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
          {incident.status !== "archived" && !incident.investigation_id && !incident.investigation && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setLaunchIncident(incident);
                setLaunchTargetHost(incident.hostnames?.[0] || "");
                setLaunchTargetUser("root");
                setLaunchDialogOpen(true);
              }}
            >
              <Play className="mr-1 h-3 w-3" />
              Investigate
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              router.push(`/incidents/${incident.id}`);
            }}
          >
            View
            <ArrowRight className="ml-1 h-4 w-4" />
          </Button>
        </div>
      ),
      className: "w-44",
    },
  ];

  const clearFilters = () => {
    setStatus("all");
    setSeverity("all");
    setWhitelisted("all");
    setTimePreset("all");
    setOffset(0);
  };

  const hasFilters = status !== "all" || severity !== "all" || whitelisted !== "all" || timePreset !== "all";

  return (
    <div className="flex flex-col">
      <PageHeader
        icon={FileWarning}
        title="Incidents"
        description="Security incidents requiring investigation"
        onRefresh={() => mutate()}
        isLoading={isLoading}
        actions={
          <div className="flex items-center gap-2">
            <Select value={status} onValueChange={(v) => { setStatus(v); setOffset(0); }}>
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
            <Select value={severity} onValueChange={(v) => { setSeverity(v); setOffset(0); }}>
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
            <Select value={whitelisted} onValueChange={(v) => { setWhitelisted(v); setOffset(0); }}>
              <SelectTrigger className="w-40 max-sm:w-full">
                <SelectValue placeholder="Whitelist" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="true">Whitelisted</SelectItem>
                <SelectItem value="false">Not Whitelisted</SelectItem>
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

      <div className="flex-1 p-6">
        {error ? (
          <ErrorState
            title="Failed to load incidents"
            error={error}
            onRetry={() => mutate()}
          />
        ) : (
          <DataTable
            columns={columns}
            data={incidents}
            page={currentPage}
            totalPages={totalPages}
            totalItems={total}
            onPageChange={handlePageChange}
            onRowClick={(incident) => router.push(`/incidents/${incident.id}`)}
            isLoading={isLoading}
            emptyMessage="No incidents found"
          />
        )}
      </div>

      {/* Launch Investigation Dialog */}
      <Dialog open={launchDialogOpen} onOpenChange={setLaunchDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Start Investigation</DialogTitle>
            <DialogDescription>
              This will spawn an AI investigation and may auto-generate remediation playbooks.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            {launchIncident && (
              <div className="rounded-lg border bg-muted/50 p-3 space-y-1">
                <p className="text-sm font-medium">{launchIncident.title}</p>
                <p className="text-xs text-muted-foreground">
                  {launchIncident.alert_count} linked alert{launchIncident.alert_count !== 1 ? "s" : ""}
                </p>
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="target_host">Target Host</Label>
              <Input
                id="target_host"
                placeholder="e.g. 192.168.1.10"
                value={launchTargetHost}
                onChange={(e) => setLaunchTargetHost(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="target_user">Target User</Label>
              <Input
                id="target_user"
                placeholder="e.g. root"
                value={launchTargetUser}
                onChange={(e) => setLaunchTargetUser(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setLaunchDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={launchLoading || !launchTargetHost.trim() || !launchTargetUser.trim()}
              onClick={async () => {
                if (!launchIncident) return;
                setLaunchLoading(true);
                try {
                  const inv = await investigationsAPI.createManual({
                    incident_id: launchIncident.id,
                    target_host: launchTargetHost.trim(),
                    target_user: launchTargetUser.trim(),
                  });
                  toast({ title: "Investigation launched", description: `ID: ${inv.investigation_id}` });
                  setLaunchDialogOpen(false);
                  router.push(`/investigations/${inv.investigation_id}`);
                } catch (e: any) {
                  toast({
                    title: "Failed to launch investigation",
                    description: e?.message || "Something went wrong",
                    variant: "destructive",
                  });
                } finally {
                  setLaunchLoading(false);
                }
              }}
            >
              {launchLoading ? "Starting..." : "Start Investigation"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default function IncidentsPage() {
  return (
    <Suspense fallback={<ListPageSkeleton filterCount={3} />}>
      <IncidentsPageInner />
    </Suspense>
  );
}
