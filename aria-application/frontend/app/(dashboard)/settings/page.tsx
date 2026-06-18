"use client";

import Link from "next/link";
import useSWR from "swr";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { settingsAPI, type SettingsOverview } from "@/lib/api";
import {
  Shield,
  Database,
  HardDrive,
  Brain,
  Terminal,
  Workflow,
  Activity,
  GitBranch,
  Server,
} from "lucide-react";
import { SettingsPageSkeleton } from "@/components/page-skeletons";
import { cn } from "@/lib/utils";

const cards = [
  { key: "security" as const, label: "Security", icon: Shield, href: "/settings/security" },
  { key: "assets" as const, label: "Assets", icon: Server, href: "/settings/assets" },
  { key: "data_sources" as const, label: "Data Sources", icon: Database, href: "/settings/data-sources" },
  { key: "redis" as const, label: "Redis", icon: HardDrive, href: "/settings/redis" },
  { key: "ai" as const, label: "AI", icon: Brain, href: "/settings/ai" },
  { key: "ansible" as const, label: "Ansible", icon: Terminal, href: "/settings/ansible" },
  { key: "workflow" as const, label: "Workflow", icon: Workflow, href: "/settings/workflow" },
  { key: "monitoring" as const, label: "Monitoring", icon: Activity, href: "/settings/monitoring" },
  { key: "pipeline" as const, label: "Pipeline", icon: GitBranch, href: "/settings/pipeline" },
];

function statusColor(status: string) {
  const s = status.toLowerCase();
  if (s === "protected" || s === "connected" || s === "ready" || s === "active" || s === "ok" || s === "running" || s === "success")
    return "bg-emerald-500/10 text-emerald-500 border-emerald-500/20";
  if (s === "warning" || s === "degraded" || s === "modified" || s === "paused" || s === "disabled")
    return "bg-amber-500/10 text-amber-500 border-amber-500/20";
  return "bg-red-500/10 text-red-500 border-red-500/20";
}

export default function SettingsOverviewPage() {
  const { data, isLoading } = useSWR<SettingsOverview>("settings-overview", () => settingsAPI.getOverview(), {
    refreshInterval: 30000,
  });

  return (
    <div>
      <PageHeader title="Settings" description="Manage ARIA runtime configuration" />
      <div className="p-6">
        {isLoading && <SettingsPageSkeleton cardCount={cards.length} />}
        {!isLoading && <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {cards.map((c) => {
            const info = data?.[c.key];
            const status = info?.status ?? "unknown";
            return (
              <Link key={c.key} href={c.href} className="block">
                <Card className={cn("border transition-shadow hover:shadow-md cursor-pointer", statusColor(status))}>
                  <CardHeader className="flex flex-row items-center justify-between pb-2">
                    <CardTitle className="text-sm font-medium">{c.label}</CardTitle>
                    <c.icon className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold capitalize">{status}</div>
                    {info?.detail && (
                      <p className="text-xs text-muted-foreground mt-1">{info.detail}</p>
                    )}

                  </CardContent>
                </Card>
              </Link>
            );
          })}
        </div>}
      </div>
    </div>
  );
}
