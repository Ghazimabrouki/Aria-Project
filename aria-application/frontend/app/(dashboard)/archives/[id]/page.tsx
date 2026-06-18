"use client";

import { use } from "react";
import useSWR from "swr";
import { useRouter } from "next/navigation";
import { format, formatDistanceToNow } from "date-fns";
import {
  ArrowLeft,
  Archive,
  Clock,
  Shield,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  FileText,
  ChevronRight,
  ExternalLink,
  Server,
  Globe,
  Tag,
  Download,
} from "lucide-react";
import {
  archivesAPI,
  type ArchiveDetailResponse,
  type Alert,
} from "@/lib/api";
import { PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { RiskAssessmentCard } from "@/components/risk-assessment-card";
import { AttackNarrativeCard } from "@/components/attack-narrative-card";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";

function parseGroundingWarning(text: string): { summary: string; warning: string | null } {
  const match = text.match(/\[GROUNDING WARNING:[^\]]*\]/);
  if (match) {
    return {
      summary: text.replace(match[0], "").replace(/\s+/g, " ").trim(),
      warning: match[0].slice(1, -1).replace(/^GROUNDING WARNING:\s*/, ""),
    };
  }
  return { summary: text, warning: null };
}

function AISummaryCard({ text }: { text: string }) {
  const { summary, warning } = parseGroundingWarning(text);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-medium">AI Summary</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm text-muted-foreground leading-relaxed">{summary}</p>
        {warning && (
          <div className="rounded-md border border-amber-300 bg-amber-50 dark:bg-amber-950/20 dark:border-amber-800 p-3">
            <div className="flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-600 shrink-0 mt-0.5" />
              <div>
                <p className="text-xs font-medium text-amber-700 dark:text-amber-300">Grounding Warning</p>
                <p className="text-xs text-amber-700/80 dark:text-amber-400/80 mt-0.5">{warning}</p>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function FixStatusBadge({ status }: { status: string }) {
  const config =
    {
      likely_fixed: {
        icon: CheckCircle2,
        className: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
        label: "Likely Fixed",
      },
      verified: {
        icon: CheckCircle2,
        className: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
        label: "Verified",
      },
      not_fixed: {
        icon: XCircle,
        className: "bg-destructive/10 text-destructive border-destructive/20",
        label: "Not Fixed",
      },
      declined: {
        icon: XCircle,
        className: "bg-destructive/10 text-destructive border-destructive/20",
        label: "Declined",
      },
      inconclusive: {
        icon: HelpCircle,
        className: "bg-warning/10 text-warning border-warning/20",
        label: "Inconclusive",
      },
      playbook_failed_but_quiet: {
        icon: HelpCircle,
        className: "bg-warning/10 text-warning border-warning/20",
        label: "Failed but Quiet",
      },
      playbook_failed_problem_worse: {
        icon: XCircle,
        className: "bg-destructive/10 text-destructive border-destructive/20",
        label: "Failed & Worse",
      },
      unknown: {
        icon: HelpCircle,
        className: "bg-muted text-muted-foreground border-border",
        label: "Unknown",
      },
    }[status] || {
      icon: HelpCircle,
      className: "bg-muted text-muted-foreground border-border",
      label: status,
    };

  const Icon = config.icon;

  return (
    <Badge variant="outline" className={cn("gap-1", config.className)}>
      <Icon className="h-3 w-3" />
      {config.label}
    </Badge>
  );
}

export default function ArchiveDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const router = useRouter();

  const { data, isLoading, error, mutate } = useSWR<ArchiveDetailResponse>(
    ["archive", id],
    () => archivesAPI.get(id)
  );

  const { data: alertsData, isLoading: alertsLoading } = useSWR<{ alerts: Alert[]; total: number }>(
    ["archive-alerts", id],
    () => archivesAPI.getAlerts(id)
  );

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader
          title="Archive Not Found"
          description="Unable to load archive details"
          actions={
            <Button variant="outline" onClick={() => router.back()}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
          }
        />
        <div className="flex-1 flex items-center justify-center p-6">
          <Card className="max-w-md w-full">
            <CardContent className="py-12 text-center">
              <p className="text-destructive font-medium">Failed to load archive</p>
              <p className="text-sm text-muted-foreground mt-1">
                {error instanceof Error ? error.message : "Unknown error"}
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  const archive = data;
  const investigation = archive.full_context?.investigation;
  const incident = archive.full_context?.incident;
  const alerts = alertsData?.alerts || [];
  const archiveTitle = investigation?.incident_title || incident?.title || archive.incident_title || archive.incident_id;
  const displayTitle = archiveTitle && archiveTitle.length > 50 ? `${archiveTitle.substring(0, 50)}...` : archiveTitle;

  return (
    <div className="flex flex-col">
      <PageHeader
        title={`Archive: ${displayTitle}`}
        description={`Archived ${(() => {
          const d = archive.archived_at ? new Date(archive.archived_at) : null;
          return d && !isNaN(d.getTime()) ? formatDistanceToNow(d, { addSuffix: true }) : "—";
        })()}`}
        onRefresh={() => mutate()}
        backHref="/archives"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" asChild>
              <a href={`${process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8001"}/api/v1/reports/archives/${id}/pdf`} download>
                <Download className="mr-2 h-4 w-4" />
                PDF
              </a>
            </Button>
            <Button variant="outline" size="sm" onClick={() => router.back()}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
          </div>
        }
      />

      <div className="flex-1 space-y-6 p-6">
        {/* Overview Cards */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Severity</p>
                  <SeverityBadge severity={archive.severity} />
                </div>
                <AlertTriangle className="h-8 w-8 text-muted-foreground/30" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Fix Status</p>
                  <FixStatusBadge status={archive.fix_status} />
                </div>
                <Shield className="h-8 w-8 text-muted-foreground/30" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Related Alerts</p>
                  <p className="text-2xl font-bold">{alertsData?.total ?? alerts.length}</p>
                </div>
                <FileText className="h-8 w-8 text-muted-foreground/30" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Archived</p>
                  <p className="text-sm font-medium">
                    {(() => {
                      const d = archive.archived_at ? new Date(archive.archived_at) : null;
                      return d && !isNaN(d.getTime()) ? format(d, "PPp") : "—";
                    })()}
                  </p>
                </div>
                <Clock className="h-8 w-8 text-muted-foreground/30" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Fix Details */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5 text-emerald-500" />
              <CardTitle className="text-base font-medium">Verification Result</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground">{archive.fix_detail || (archive.fix_status ? `Fix status: ${archive.fix_status}` : "No fix details available")}</p>
          </CardContent>
        </Card>

        {/* Related Items Links */}
        <div className="grid gap-4 md:grid-cols-2">
          {incident && (
            <Card className="border-primary/30 bg-primary/5">
              <CardContent className="flex items-center justify-between py-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                    <FileText className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <p className="font-medium">Original Incident</p>
                    <p className="text-sm text-muted-foreground truncate max-w-[200px]">
                      {incident.title}
                    </p>
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => router.push(`/incidents/${archive.incident_id}`)}
                >
                  View
                  <ChevronRight className="ml-1 h-4 w-4" />
                </Button>
              </CardContent>
            </Card>
          )}
          {investigation && (
            <Card className="border-blue-500/30 bg-blue-500/5">
              <CardContent className="flex items-center justify-between py-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-500/10">
                    <Shield className="h-5 w-5 text-blue-500" />
                  </div>
                  <div>
                    <p className="font-medium">Investigation</p>
                    <p className="text-sm text-muted-foreground">
                      {archive.investigation_id}
                    </p>
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => investigation?.id && router.push(`/investigations/${investigation.id}`)}
                  disabled={!investigation?.id}
                >
                  View
                  <ChevronRight className="ml-1 h-4 w-4" />
                </Button>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Tabs for detailed information */}
        <Tabs defaultValue="ai-analysis" className="space-y-4">
          <TabsList>
            <TabsTrigger value="ai-analysis">AI Analysis</TabsTrigger>
            <TabsTrigger value="playbook">Playbook</TabsTrigger>
            <TabsTrigger value="alerts">Alerts ({alertsData?.total ?? alerts.length})</TabsTrigger>
            <TabsTrigger value="incident">Incident Details</TabsTrigger>
          </TabsList>

          <TabsContent value="ai-analysis" className="space-y-4">
            {investigation ? (
              <div className="grid gap-4 lg:grid-cols-2">
                {/* Summary */}
                {investigation.ai_summary ? (
                  <AISummaryCard text={investigation.ai_summary} />
                ) : (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base font-medium">AI Summary</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-muted-foreground">No AI summary available</p>
                    </CardContent>
                  </Card>
                )}

                {/* Risk Assessment */}
                {investigation.ai_risk ? (
                  <RiskAssessmentCard text={investigation.ai_risk} />
                ) : (
                  <Card className="border-destructive/30">
                    <CardHeader>
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="h-5 w-5 text-destructive" />
                        <CardTitle className="text-base font-medium">Risk Assessment</CardTitle>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <p className="text-muted-foreground">No risk assessment available</p>
                    </CardContent>
                  </Card>
                )}

                {/* Narrative */}
                {investigation.ai_narrative ? (
                  <div className="lg:col-span-2">
                    <AttackNarrativeCard text={investigation.ai_narrative} />
                  </div>
                ) : (
                  <Card className="lg:col-span-2">
                    <CardHeader>
                      <CardTitle className="text-base font-medium">Attack Narrative</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-muted-foreground">No narrative available</p>
                    </CardContent>
                  </Card>
                )}

                {/* Source IPs */}
                {investigation.source_ips && investigation.source_ips.length > 0 && (
                  <Card>
                    <CardHeader>
                      <div className="flex items-center gap-2">
                        <Globe className="h-5 w-5 text-warning" />
                        <CardTitle className="text-base font-medium">Source IPs</CardTitle>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="flex flex-wrap gap-2">
                        {(() => {
                          const ipsRaw = (investigation as any).source_ips;
                          const ipsList = Array.isArray(ipsRaw)
                            ? ipsRaw
                            : typeof ipsRaw === "string"
                              ? ipsRaw.split(",").map((s: string) => s.trim()).filter(Boolean)
                              : [];
                          return ipsList;
                        })().map((ip: string, index: number) => (
                          <Badge
                            key={index}
                            variant="outline"
                            className="font-mono cursor-pointer hover:bg-accent"
                            onClick={() => router.push(`/search?q=${ip}`)}
                          >
                            {ip}
                            <ExternalLink className="ml-1 h-3 w-3" />
                          </Badge>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Target Host */}
                {investigation.target_host && (
                  <Card>
                    <CardHeader>
                      <div className="flex items-center gap-2">
                        <Server className="h-5 w-5 text-primary" />
                        <CardTitle className="text-base font-medium">Target Host</CardTitle>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <Badge variant="secondary" className="font-mono">
                        {investigation.target_host}
                      </Badge>
                    </CardContent>
                  </Card>
                )}
              </div>
            ) : (
              <Card>
                <CardContent className="py-12 text-center">
                  <p className="text-muted-foreground">No investigation data available</p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="playbook">
            {investigation?.playbook_yaml ? (
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base font-medium">Executed Playbook</CardTitle>
                    {investigation.playbook_valid ? (
                      <Badge variant="outline" className="bg-emerald-500/10 text-emerald-500">
                        <CheckCircle2 className="mr-1 h-3 w-3" />
                        Valid
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="bg-destructive/10 text-destructive">
                        <XCircle className="mr-1 h-3 w-3" />
                        Invalid
                      </Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[400px]">
                    <pre className="rounded-lg bg-muted p-4 text-sm font-mono overflow-x-auto">
                      {investigation.playbook_yaml}
                    </pre>
                  </ScrollArea>
                </CardContent>
              </Card>
            ) : (
              <Card>
                <CardContent className="py-12 text-center">
                  <p className="text-muted-foreground">No playbook data available</p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="alerts">
            <Card>
              <CardHeader>
                <CardTitle className="text-base font-medium">Related Alerts</CardTitle>
              </CardHeader>
              <CardContent>
                {alertsLoading ? (
                  <div className="flex items-center justify-center py-12">
                    <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                  </div>
                ) : alerts.length > 0 ? (
                  <ScrollArea className="h-[400px] pr-4">
                    <div className="space-y-3">
                      {alerts.map((alert) => (
                        <div
                          key={alert.id}
                          className="flex items-start justify-between rounded-lg border border-border/50 bg-card/50 p-4 transition-colors hover:bg-accent/50 cursor-pointer"
                          onClick={() => router.push(`/alerts?id=${alert.id}`)}
                        >
                          <div className="flex items-start gap-3 flex-1 min-w-0">
                            <SeverityBadge severity={alert.severity} />
                            <div className="space-y-1 min-w-0">
                              <p className="font-medium truncate">{alert.title}</p>
                              <p className="text-sm text-muted-foreground truncate">
                                {alert.description}
                              </p>
                              <div className="flex items-center gap-2 flex-wrap">
                                <Badge variant="outline" className="text-xs">
                                  {alert.source}
                                </Badge>
                                <span className="text-xs text-muted-foreground font-mono">
                                  {alert.source_ip}{alert.dest_ip ? ` → ${alert.dest_ip}` : ""}
                                </span>
                              </div>
                              <div className="flex flex-wrap gap-1 mt-2">
                                {alert.tags?.slice(0, 3).map((tag, index) => (
                                  <Badge key={index} variant="secondary" className="text-xs">
                                    <Tag className="mr-1 h-2 w-2" />
                                    {tag}
                                  </Badge>
                                ))}
                                {alert.tags && alert.tags.length > 3 && (
                                  <Badge variant="secondary" className="text-xs">
                                    +{alert.tags.length - 3}
                                  </Badge>
                                )}
                              </div>
                            </div>
                          </div>
                          <div className="text-xs text-muted-foreground ml-4 shrink-0">
                            {alert.created_at ? formatDistanceToNow(new Date(alert.created_at), { addSuffix: true }) : "Unknown time"}
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                ) : (
                  <div className="py-12 text-center">
                    <p className="text-muted-foreground">No alerts available</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="incident">
            {incident ? (
              <div className="grid gap-4 lg:grid-cols-2">
                <Card className="lg:col-span-2">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base font-medium">{incident.title}</CardTitle>
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={incident.severity} />
                        <StatusBadge status={incident.status} />
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-muted-foreground">{incident.description}</p>

                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                      <div>
                        <p className="text-sm text-muted-foreground">Alert Count</p>
                        <p className="text-lg font-semibold">
                          {incident.alert_count ?? alertsData?.total ?? archive.full_context?.alerts?.length ?? 0}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">Assigned To</p>
                        <p className="text-lg font-semibold">
                          {incident.assigned_username || incident.resolved_by || "Unassigned"}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">Created</p>
                        <p className="text-sm font-medium">
                          {(() => {
                            const d = incident.created_at ? new Date(incident.created_at) : null;
                            return d && !isNaN(d.getTime()) ? format(d, "PPp") : "—";
                          })()}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">Closed</p>
                        <p className="text-sm font-medium">
                          {(() => {
                            const closedRaw = incident.closed_at || incident.resolved_at || incident.archived_at;
                            const d = closedRaw ? new Date(closedRaw) : null;
                            return d && !isNaN(d.getTime()) ? format(d, "PPp") : "Not closed";
                          })()}
                        </p>
                      </div>
                    </div>

                    {incident.tags && incident.tags.length > 0 && (
                      <div>
                        <p className="text-sm text-muted-foreground mb-2">Tags</p>
                        <div className="flex flex-wrap gap-2">
                          {incident.tags.map((tag, index) => (
                            <Badge key={index} variant="secondary">
                              <Tag className="mr-1 h-3 w-3" />
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
            ) : (
              <Card>
                <CardContent className="py-12 text-center">
                  <p className="text-muted-foreground">No incident data available</p>
                </CardContent>
              </Card>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
