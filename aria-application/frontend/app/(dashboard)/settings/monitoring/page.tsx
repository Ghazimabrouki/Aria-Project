"use client";

import { useCallback } from "react";
import useSWR from "swr";
import { formatDistanceToNow } from "date-fns";
import {
  Server,
  Database,
  Search,
  Brain,
  Workflow,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Clock,
} from "lucide-react";
import { monitoringAPI, type ServiceHealth, type ServiceStatus } from "@/lib/api";
import { useWSSubscription, type WSMessage } from "@/lib/websocket";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const serviceIcons: Record<string, React.ElementType> = {
  "API Server": Server,
  "Alert Forwarder": Database,
  "Incident Watcher": Shield,
  "Incident Correlation": Workflow,
  "Auto Transitions": Workflow,
  "Retry Queue": Database,
  "Database Backup": Database,
  "Health Monitor": Server,
  "Performance Monitoring": Server,
  "Performance Watcher": Server,
};

function mapServiceStatus(name: string, svc: ServiceStatus): ServiceHealth {
  const statusMap: Record<ServiceStatus["status"], ServiceHealth["status"]> = {
    running: "healthy",
    stopped: "down",
    error: "degraded",
    disabled: "down",
    idle: "healthy",
  };
  return {
    name: svc.name || name,
    status: statusMap[svc.status] || "degraded",
    latency_ms: svc.latency_ms ?? (svc.poll_interval ? svc.poll_interval * 1000 : 0),
    last_check: svc.last_check || new Date().toISOString(),
    details: svc.details,
  };
}

export default function MonitoringSettingsPage() {
  const {
    data: servicesStatus,
    isLoading,
    error,
    mutate,
  } = useSWR<{
    services: Record<string, ServiceStatus>;
    timestamp?: string;
  }>("service-health", () => monitoringAPI.getServicesStatus(), {
    refreshInterval: 15000,
  });

  const handleWSUpdate = useCallback((message: WSMessage) => {
    mutate();
  }, [mutate]);

  const serviceList: ServiceHealth[] = servicesStatus?.services
    ? Object.entries(servicesStatus.services).map(([key, svc]) =>
        mapServiceStatus(key, svc)
      )
    : [];

  const healthyCount = serviceList.filter((s) => s.status === "healthy").length;
  const degradedCount = serviceList.filter((s) => s.status === "degraded").length;
  const downCount = serviceList.filter((s) => s.status === "down").length;
  const disabledCount = Object.values(servicesStatus?.services || {}).filter(
    (s) => s.status === "disabled"
  ).length;

  return (
    <div className="flex flex-col">
      <PageHeader
        title="Monitoring"
        description="Backend services health status"
        onRefresh={() => mutate()}
        isLoading={isLoading}
      />

      <div className="flex-1 space-y-6 p-6">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card className={cn(healthyCount === serviceList.length && serviceList.length > 0 && "border-success/50 bg-success/5")}>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Healthy Services</p>
                  <p className="text-3xl font-bold text-success">{healthyCount}</p>
                </div>
                <CheckCircle2 className="h-10 w-10 text-success/30" />
              </div>
            </CardContent>
          </Card>
          <Card className={cn(degradedCount > 0 && "border-warning/50 bg-warning/5")}>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Degraded</p>
                  <p className={cn("text-3xl font-bold", degradedCount > 0 ? "text-warning" : "text-foreground")}>
                    {degradedCount}
                  </p>
                </div>
                <Clock className={cn("h-10 w-10", degradedCount > 0 ? "text-warning/30" : "text-muted-foreground/30")} />
              </div>
            </CardContent>
          </Card>
          <Card className={cn(downCount > 0 && "border-destructive/50 bg-destructive/5")}>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Down</p>
                  <p className={cn("text-3xl font-bold", downCount > 0 ? "text-destructive" : "text-foreground")}>
                    {downCount}
                  </p>
                </div>
                <AlertTriangle className={cn("h-10 w-10", downCount > 0 ? "text-destructive/30" : "text-muted-foreground/30")} />
              </div>
            </CardContent>
          </Card>
          <Card className={cn(disabledCount > 0 && "border-muted bg-muted/50")}>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Disabled</p>
                  <p className={cn("text-3xl font-bold", disabledCount > 0 ? "text-muted-foreground" : "text-foreground")}>
                    {disabledCount}
                  </p>
                </div>
                <Server className={cn("h-10 w-10", disabledCount > 0 ? "text-muted-foreground/30" : "text-muted-foreground/30")} />
              </div>
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="text-base font-medium">All Services</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">{Array.from({ length: 6 }).map((_, i) => (<div key={i} className="rounded-lg border p-4 space-y-3"><div className="h-4 w-24 bg-muted rounded" /><div className="h-3 w-full bg-muted rounded" /><div className="h-3 w-2/3 bg-muted rounded" /></div>))}</div>
            ) : error ? (
              <div className="text-sm text-destructive">
                Failed to load services. {error instanceof Error ? error.message : ""}
              </div>
            ) : serviceList.length === 0 ? (
              <div className="text-sm text-muted-foreground">No services available.</div>
            ) : (
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                {serviceList.map((service) => (
                  <ServiceCard key={service.name} service={service} />
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base font-medium">Service Details</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">{Array.from({ length: 6 }).map((_, i) => (<div key={i} className="rounded-lg border p-4 space-y-3"><div className="h-4 w-24 bg-muted rounded" /><div className="h-3 w-full bg-muted rounded" /><div className="h-3 w-2/3 bg-muted rounded" /></div>))}</div>
            ) : error ? (
              <div className="text-sm text-destructive">
                Failed to load services. {error instanceof Error ? error.message : ""}
              </div>
            ) : serviceList.length === 0 ? (
              <div className="text-sm text-muted-foreground">No services available.</div>
            ) : (
              <div className="space-y-3">
                {serviceList.map((service) => {
                  const Icon = serviceIcons[service.name] || Server;
                  return (
                    <div
                      key={service.name}
                      className={cn(
                        "flex items-center justify-between rounded-lg border p-4",
                        service.status === "healthy" && "border-success/30",
                        service.status === "degraded" && "border-warning/30 bg-warning/5",
                        service.status === "down" && "border-destructive/30 bg-destructive/5"
                      )}
                    >
                      <div className="flex items-center gap-4">
                        <div
                          className={cn(
                            "flex h-12 w-12 items-center justify-center rounded-lg",
                            service.status === "healthy" && "bg-success/10 text-success",
                            service.status === "degraded" && "bg-warning/10 text-warning",
                            service.status === "down" && "bg-destructive/10 text-destructive"
                          )}
                        >
                          <Icon className="h-6 w-6" />
                        </div>
                        <div>
                          <p className="font-medium">{service.name}</p>
                          {service.details && (
                            <p className="text-sm text-muted-foreground">{service.details}</p>
                          )}
                          {service.latency_ms > 0 && (
                            <p className="text-xs text-muted-foreground font-mono">
                              Latency: {service.latency_ms.toFixed(1)}ms
                            </p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-6">
                        <div className="text-right">
                          <p className="text-xs text-muted-foreground">Latency</p>
                          <p
                            className={cn(
                              "font-mono text-sm",
                              service.latency_ms > 100 && "text-warning",
                              service.latency_ms > 500 && "text-destructive"
                            )}
                          >
                            {service.latency_ms}ms
                          </p>
                        </div>
                        <div className="text-right">
                          <p className="text-xs text-muted-foreground">Last Check</p>
                          <p className="text-sm text-muted-foreground">
                            {service.last_check
                              ? (() => {
                                  const d = new Date(service.last_check);
                                  return !isNaN(d.getTime()) ? formatDistanceToNow(d, { addSuffix: true }) : "—";
                                })()
                              : "—"}
                          </p>
                        </div>
                        <StatusBadge status={service.status} />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function ServiceCard({ service }: { service: ServiceHealth }) {
  const Icon = serviceIcons[service.name] || Server;
  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-lg border p-4 transition-all hover:shadow-md",
        service.status === "healthy" && "border-success/30",
        service.status === "degraded" && "border-warning/30",
        service.status === "down" && "border-destructive/30"
      )}
    >
      <div className="flex items-start justify-between">
        <div
          className={cn(
            "flex h-10 w-10 items-center justify-center rounded-lg",
            service.status === "healthy" && "bg-success/10 text-success",
            service.status === "degraded" && "bg-warning/10 text-warning",
            service.status === "down" && "bg-destructive/10 text-destructive"
          )}
        >
          <Icon className="h-5 w-5" />
        </div>
        <div className="relative">
          <div
            className={cn(
              "h-3 w-3 rounded-full",
              service.status === "healthy" && "bg-success",
              service.status === "degraded" && "bg-warning",
              service.status === "down" && "bg-destructive"
            )}
          />
          {service.status === "healthy" && (
            <div className="absolute inset-0 h-3 w-3 animate-ping rounded-full bg-success opacity-50" />
          )}
        </div>
      </div>
      <div className="mt-4">
        <p className="font-medium">{service.name}</p>
        <p className="mt-1 font-mono text-sm text-muted-foreground">
          {service.latency_ms}ms
        </p>
      </div>
      <div
        className={cn(
          "absolute bottom-0 left-0 h-1 w-full",
          service.status === "healthy" && "bg-success",
          service.status === "degraded" && "bg-warning",
          service.status === "down" && "bg-destructive"
        )}
      />
    </div>
  );
}
