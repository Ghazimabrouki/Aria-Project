"use client";

import { use, useState } from "react";
import useSWR from "swr";
import { useRouter } from "next/navigation";
import { format } from "date-fns";
import { formatAbsoluteDateTime } from "@/lib/time";
import {
  ArrowLeft,
  Clock,
  AlertTriangle,
  ExternalLink,
  ChevronRight,
  Tag,
  User,
  Pencil,
  ShieldCheck,
  Play,
} from "lucide-react";
import {
  incidentsAPI,
  whitelistAPI,
  investigationsAPI,
  type IncidentDetailResponse,
  type Alert,
  type IncidentTimeline,
  type Investigation,
  type TimelineEvent,
} from "@/lib/api";
import { PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { WhitelistBadge } from "@/components/whitelist-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

function getEventConfig(eventType: string) {
  const configs: Record<string, { color: string; label: string }> = {
    created: { color: "bg-primary", label: "Created" },
    incident_created: { color: "bg-primary", label: "Incident Created" },
    alert_added: { color: "bg-warning", label: "Alert Added" },
    alerts_linked: { color: "bg-warning", label: "Alerts Linked" },
    critical_alerts: { color: "bg-destructive", label: "Critical Alerts" },
    investigation_started: { color: "bg-blue-500", label: "Investigation Started" },
    investigation_created: { color: "bg-blue-500", label: "Investigation Created" },
    ai_completed: { color: "bg-emerald-500", label: "AI Completed" },
    ai_analysis_complete: { color: "bg-emerald-500", label: "AI Analysis" },
    approved: { color: "bg-emerald-500", label: "Approved" },
    playbook_approved: { color: "bg-emerald-500", label: "Playbook Approved" },
    awaiting_approval: { color: "bg-warning", label: "Awaiting Approval" },
    declined: { color: "bg-destructive", label: "Declined" },
    remediation_completed: { color: "bg-emerald-500", label: "Remediation Complete" },
    playbook_generated: { color: "bg-primary", label: "Playbook Generated" },
    verification_complete: { color: "bg-emerald-500", label: "Verification Complete" },
    status_changed: { color: "bg-muted-foreground", label: "Status Changed" },
    closed: { color: "bg-muted-foreground", label: "Closed" },
  };
  return configs[eventType] || { color: "bg-muted-foreground", label: eventType.replace(/_/g, " ") };
}

function formatEventDate(timestamp: string | undefined | null) {
  if (!timestamp) return "Unknown time";
  try {
    return format(new Date(timestamp), "PPpp");
  } catch {
    return "Invalid date";
  }
}

export default function IncidentDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const router = useRouter();

  const { data: incidentData, error: incidentError, isLoading: incidentLoading, mutate } = useSWR<IncidentDetailResponse>(
    ["incident", id],
    () => incidentsAPI.get(id),
    { refreshInterval: 30000 }
  );

  const { data: alertsData, error: alertsError, isLoading: alertsLoading } = useSWR(
    ["incident-alerts", id],
    () => incidentsAPI.getAlerts(id),
    { refreshInterval: 30000 }
  );

  const { data: timelineData, error: timelineError, isLoading: timelineLoading } = useSWR<IncidentTimeline>(
    ["incident-timeline", id],
    () => incidentsAPI.getTimeline(id),
    { refreshInterval: 30000 }
  );

  const { data: investigationsData, error: investigationsError, isLoading: investigationsLoading } = useSWR(
    ["incident-investigations", id],
    () => incidentsAPI.getInvestigations(id),
    { refreshInterval: 30000 }
  );

  const [assignOpen, setAssignOpen] = useState(false);
  const [assignName, setAssignName] = useState("");
  const [assignLoading, setAssignLoading] = useState(false);
  const [addingWhitelistIp, setAddingWhitelistIp] = useState<string | null>(null);
  const [launchOpen, setLaunchOpen] = useState(false);
  const [launchHost, setLaunchHost] = useState("");
  const [launchUser, setLaunchUser] = useState("root");
  const [launchLoading, setLaunchLoading] = useState(false);
  const { toast } = useToast();

  const handleAssign = async () => {
    if (!assignName.trim()) return;
    setAssignLoading(true);
    try {
      await incidentsAPI.update(id, { assigned_username: assignName.trim() });
      mutate();
      setAssignOpen(false);
      setAssignName("");
    } catch (e) {
      console.error("Failed to assign incident:", e);
    } finally {
      setAssignLoading(false);
    }
  };

  if (incidentLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
      </div>
    );
  }

  if (incidentError || !incidentData) {
    return (
      <div className="flex h-full flex-col items-center justify-center p-6 text-center">
        <AlertTriangle className="h-12 w-12 text-destructive" />
        <p className="mt-4 text-xl font-medium">Failed to load incident</p>
        <p className="text-sm text-muted-foreground">
          {incidentError?.message || "Something went wrong. Please try again."}
        </p>
        <div className="mt-6 flex items-center gap-3">
          <Button variant="outline" onClick={() => router.back()}>
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back
          </Button>
          <Button onClick={() => mutate()}>Retry</Button>
        </div>
      </div>
    );
  }

  const incident = incidentData.data;
  const alerts = alertsData?.alerts || [];
  const timeline = timelineData;
  const investigations = investigationsData?.investigations || [];

  return (
    <div className="flex flex-col">
      <PageHeader
        title={incident.title}
        description={`Created ${formatAbsoluteDateTime(incident.created_at)}`}
        onRefresh={() => mutate()}
        backHref="/incidents"
        actions={
          <div className="flex items-center gap-2">
            {investigations.length === 0 && (
              <Button
                onClick={() => {
                  setLaunchHost(incident.source_ips?.[0] || "");
                  setLaunchUser("root");
                  setLaunchOpen(true);
                }}
              >
                <Play className="mr-2 h-4 w-4" />
                Launch Investigation
              </Button>
            )}
            <Button variant="outline" onClick={() => router.back()}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
          </div>
        }
      />

      <div className="flex-1 space-y-6 p-6">
        {/* Overview Cards */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Severity</p>
                  <SeverityBadge severity={incident.severity} />
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Status</p>
                  <StatusBadge status={incident.status} />
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Related Alerts</p>
                  <p className="text-2xl font-bold">{incident.alert_count}</p>
                </div>
                <AlertTriangle className="h-8 w-8 text-muted-foreground/50" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Assignee</p>
                  <div className="flex items-center gap-2">
                    <User className="h-4 w-4 text-muted-foreground" />
                    <span className="font-medium">
                      {incident.assigned_username || "Unassigned"}
                    </span>
                  </div>
                </div>
                <Button variant="ghost" size="sm" onClick={() => setAssignOpen(true)}>
                  <Pencil className="h-3.5 w-3.5" />
                </Button>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Created</p>
                  <p className="text-sm font-medium">
                    {(() => {
                      const d = incident.created_at ? new Date(incident.created_at) : null;
                      return d && !isNaN(d.getTime()) ? format(d, "PPp") : "—";
                    })()}
                  </p>
                </div>
                <Clock className="h-8 w-8 text-muted-foreground/50" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Whitelist Status</p>
                  {incident.whitelisted ? (
                    <div className="flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400">
                      <ShieldCheck className="h-4 w-4" />
                      <span className="text-sm font-medium">Whitelisted</span>
                    </div>
                  ) : (
                    <span className="text-sm text-muted-foreground">Not whitelisted</span>
                  )}
                </div>
                <ShieldCheck className={cn("h-8 w-8", incident.whitelisted ? "text-emerald-500/50" : "text-muted-foreground/50")} />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Active Investigations */}
        {investigations.length > 0 && (
          <Card className="border-primary/50 bg-primary/5">
            <CardContent className="py-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                    <ExternalLink className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <p className="font-medium">
                      {investigations.length} Active Investigation{investigations.length > 1 ? "s" : ""}
                    </p>
                    <p className="text-sm text-muted-foreground">
                      {investigations[0].status === "awaiting_approval"
                        ? "Playbook ready for review"
                        : `Status: ${investigations[0].status}`}
                    </p>
                  </div>
                </div>
                <Button
                  variant={investigations[0].status === "awaiting_approval" ? "default" : "outline"}
                  onClick={() => router.push(`/investigations/${investigations[0].id}`)}
                >
                  {investigations[0].status === "awaiting_approval" ? "Review" : "View"} Investigation
                  <ChevronRight className="ml-1 h-4 w-4" />
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Tags */}
        {incident.tags && incident.tags.length > 0 && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base font-medium">Tags</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {incident.tags.map((tag, index) => (
                  <Badge key={index} variant="secondary">
                    <Tag className="mr-1 h-3 w-3" />
                    {tag}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        <Tabs defaultValue="timeline" className="space-y-4">
          <TabsList>
            <TabsTrigger value="timeline">Timeline</TabsTrigger>
            <TabsTrigger value="alerts">Alerts ({alerts.length})</TabsTrigger>
            <TabsTrigger value="investigations">Investigations ({investigations.length})</TabsTrigger>
            <TabsTrigger value="description">Description</TabsTrigger>
          </TabsList>

          <TabsContent value="timeline">
            <Card>
              <CardHeader>
                <CardTitle className="text-base font-medium">
                  Incident Timeline {timeline ? `(${timeline.total_events} events)` : ""}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {timelineLoading ? (
                  <div className="flex h-[400px] items-center justify-center">
                    <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                  </div>
                ) : timelineError ? (
                  <div className="flex h-[400px] flex-col items-center justify-center text-center">
                    <AlertTriangle className="h-10 w-10 text-destructive" />
                    <p className="mt-2 text-sm font-medium">Failed to load timeline</p>
                    <p className="text-xs text-muted-foreground">
                      {timelineError.message || "Something went wrong."}
                    </p>
                  </div>
                ) : timeline && timeline.events.length > 0 ? (
                  <ScrollArea className="h-[400px] pr-4">
                    <div className="relative space-y-4 pl-6">
                      <div className="absolute left-2 top-2 h-[calc(100%-16px)] w-px bg-border" />
                      {timeline.events.map((event: TimelineEvent, index: number) => {
                        const eventType = event.event || event.type || "";
                        const eventDetails = event.details || event.description || "";
                        const config = getEventConfig(eventType);
                        return (
                          <div key={index} className="relative">
                            <div
                              className={cn(
                                "absolute -left-6 top-1 h-3 w-3 rounded-full border-2 border-background",
                                config.color
                              )}
                            />
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <Badge variant="outline" className="text-xs">
                                  {config.label}
                                </Badge>
                                {event.investigation_id && (
                                  <Badge
                                    variant="secondary"
                                    className="text-xs cursor-pointer"
                                    onClick={() => router.push(`/investigations/${event.investigation_id}`)}
                                  >
                                    {event.investigation_id}
                                    <ExternalLink className="ml-1 h-2 w-2" />
                                  </Badge>
                                )}
                              </div>
                              <p className="text-sm">{eventDetails}</p>
                              <p className="text-xs text-muted-foreground">
                                {formatEventDate(event.timestamp)}
                              </p>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </ScrollArea>
                ) : (
                  <div className="flex h-[400px] flex-col items-center justify-center text-center">
                    <Clock className="h-10 w-10 text-muted-foreground/50" />
                    <p className="mt-2 text-sm font-medium">No timeline events</p>
                    <p className="text-xs text-muted-foreground">
                      There are no events recorded for this incident yet.
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="alerts">
            <Card>
              <CardHeader>
                <CardTitle className="text-base font-medium">
                  Related Alerts ({alerts.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                {alertsLoading ? (
                  <div className="flex h-[400px] items-center justify-center">
                    <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                  </div>
                ) : alertsError ? (
                  <div className="flex h-[400px] flex-col items-center justify-center text-center">
                    <AlertTriangle className="h-10 w-10 text-destructive" />
                    <p className="mt-2 text-sm font-medium">Failed to load alerts</p>
                    <p className="text-xs text-muted-foreground">
                      {alertsError.message || "Something went wrong."}
                    </p>
                  </div>
                ) : alerts.length > 0 ? (
                  <ScrollArea className="h-[400px] pr-4">
                    <div className="space-y-3">
                      {alerts.map((alert: Alert) => (
                        <div
                          key={alert.id}
                          className="flex items-start justify-between rounded-lg border border-border/50 bg-card/50 p-4 transition-colors hover:bg-accent/50 cursor-pointer"
                          onClick={() => router.push(`/alerts?id=${alert.id}`)}
                        >
                          <div className="flex items-start gap-3 flex-1 min-w-0">
                            <SeverityBadge severity={alert.severity} />
                            <div className="space-y-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <p className="font-medium truncate">{alert.title}</p>
                                {alert.whitelisted && <WhitelistBadge whitelisted={alert.whitelisted} />}
                              </div>
                              <div className="flex items-center gap-2 flex-wrap">
                                <Badge variant="outline" className="text-xs">
                                  {alert.source}
                                </Badge>
                                <span className="text-xs text-muted-foreground font-mono">
                                  {alert.source_ip} → {alert.hostname}
                                </span>
                              </div>
                            </div>
                          </div>
                          <div className="text-xs text-muted-foreground ml-4 shrink-0">
                            {formatAbsoluteDateTime(alert.created_at)}
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                ) : (
                  <div className="flex h-[400px] flex-col items-center justify-center text-center">
                    <AlertTriangle className="h-10 w-10 text-muted-foreground/50" />
                    <p className="mt-2 text-sm font-medium">No related alerts</p>
                    <p className="text-xs text-muted-foreground">
                      There are no alerts associated with this incident.
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="investigations">
            <Card>
              <CardHeader>
                <CardTitle className="text-base font-medium">
                  Linked Investigations ({investigations.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                {investigationsLoading ? (
                  <div className="flex h-[400px] items-center justify-center">
                    <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                  </div>
                ) : investigationsError ? (
                  <div className="flex h-[400px] flex-col items-center justify-center text-center">
                    <AlertTriangle className="h-10 w-10 text-destructive" />
                    <p className="mt-2 text-sm font-medium">Failed to load investigations</p>
                    <p className="text-xs text-muted-foreground">
                      {investigationsError.message || "Something went wrong."}
                    </p>
                  </div>
                ) : investigations.length > 0 ? (
                  <ScrollArea className="h-[400px] pr-4">
                    <div className="space-y-3">
                      {investigations.map((inv: Investigation) => (
                        <div
                          key={inv.id}
                          className="flex items-start justify-between rounded-lg border border-border/50 bg-card/50 p-4 transition-colors hover:bg-accent/50 cursor-pointer"
                          onClick={() => router.push(`/investigations/${inv.id}`)}
                        >
                          <div className="space-y-1 flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <StatusBadge status={inv.status} />
                              {inv.has_playbook && (
                                <Badge variant="outline" className="text-xs">
                                  Playbook
                                </Badge>
                              )}
                            </div>
                            {inv.ai_summary && (
                              <p className="text-sm text-muted-foreground truncate">
                                {inv.ai_summary}
                              </p>
                            )}
                            <div className="flex items-center gap-3 text-xs text-muted-foreground">
                              <span>ID: {inv.id}</span>
                              {inv.target_host && <span>Target: {inv.target_host}</span>}
                            </div>
                          </div>
                          <div className="text-xs text-muted-foreground ml-4 shrink-0">
                            {formatAbsoluteDateTime(inv.created_at)}
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                ) : (
                  <div className="flex h-[400px] flex-col items-center justify-center text-center">
                    <AlertTriangle className="h-10 w-10 text-muted-foreground/50" />
                    <p className="mt-2 text-sm font-medium">No linked investigations</p>
                    <p className="text-xs text-muted-foreground">
                      There are no investigations associated with this incident.
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="description" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base font-medium">Incident Description</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground whitespace-pre-wrap">
                  {incident.description}
                </p>
              </CardContent>
            </Card>

            {incident.source_ips && incident.source_ips.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base font-medium">Source IPs</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {incident.source_ips.map((ip) => (
                      <div key={ip} className="flex items-center justify-between">
                        <code className="bg-muted px-2 py-1 rounded text-sm font-mono">{ip}</code>
                        <Button
                          variant="outline"
                          size="sm"
                          className="text-xs"
                          disabled={addingWhitelistIp === ip}
                          onClick={async () => {
                            setAddingWhitelistIp(ip);
                            try {
                              await whitelistAPI.create({ type: "ip", value: ip, label: "trusted" });
                              mutate();
                            } catch (e) {
                              console.error("Failed to add to whitelist:", e);
                            } finally {
                              setAddingWhitelistIp(null);
                            }
                          }}
                        >
                          <ShieldCheck className="mr-1 h-3 w-3" />
                          {addingWhitelistIp === ip ? "Adding..." : "Add to Whitelist"}
                        </Button>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>
        </Tabs>

        {/* Assign Dialog */}
        <Dialog open={assignOpen} onOpenChange={setAssignOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Assign Incident</DialogTitle>
            </DialogHeader>
            <div className="py-4">
              <Input
                placeholder="Analyst name..."
                value={assignName}
                onChange={(e) => setAssignName(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleAssign()}
              />
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setAssignOpen(false)}>Cancel</Button>
              <Button onClick={handleAssign} disabled={assignLoading || !assignName.trim()}>
                {assignLoading ? "Assigning..." : "Assign"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Launch Investigation Dialog */}
        <Dialog open={launchOpen} onOpenChange={setLaunchOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Launch Investigation</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="rounded-lg border bg-muted/50 p-3 space-y-1">
                <p className="text-sm font-medium">{incident.title}</p>
                <p className="text-xs text-muted-foreground">
                  {incident.alert_count} linked alert{incident.alert_count !== 1 ? "s" : ""}
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="launch_host">Target Host</Label>
                <Input
                  id="launch_host"
                  placeholder="e.g. 192.168.1.10"
                  value={launchHost}
                  onChange={(e) => setLaunchHost(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="launch_user">Target User</Label>
                <Input
                  id="launch_user"
                  placeholder="e.g. root"
                  value={launchUser}
                  onChange={(e) => setLaunchUser(e.target.value)}
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setLaunchOpen(false)}>Cancel</Button>
              <Button
                disabled={launchLoading || !launchHost.trim() || !launchUser.trim()}
                onClick={async () => {
                  setLaunchLoading(true);
                  try {
                    const inv = await investigationsAPI.createManual({
                      incident_id: id,
                      target_host: launchHost.trim(),
                      target_user: launchUser.trim(),
                    });
                    toast({ title: "Investigation launched", description: `ID: ${inv.investigation_id}` });
                    setLaunchOpen(false);
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
                {launchLoading ? "Launching..." : "Launch Investigation"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
}
