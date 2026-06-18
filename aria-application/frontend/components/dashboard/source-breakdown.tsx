"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { SourceBreakdown } from "@/lib/api";
import { useRouter } from "next/navigation";
import { Server } from "lucide-react";

interface SourceBreakdownWidgetProps {
  data?: SourceBreakdown;
  error?: boolean;
}

const SOURCE_COLORS: Record<string, string> = {
  wazuh: "bg-chart-1",
  suricata: "bg-chart-2",
  falco: "bg-chart-3",
  other: "bg-chart-4",
};

const SOURCE_LABELS: Record<string, string> = {
  wazuh: "Wazuh",
  suricata: "Suricata",
  falco: "Falco",
  other: "Other",
};

export function SourceBreakdownWidget({ data, error }: SourceBreakdownWidgetProps) {
  const router = useRouter();

  if (error) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base font-medium flex items-center gap-2">
            <Server className="h-4 w-4 text-muted-foreground" />
            Alert Sources
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <p className="text-sm text-muted-foreground">Unable to load source breakdown.</p>
        </CardContent>
      </Card>
    );
  }

  const sources = data?.sources ?? [];
  const total = sources.reduce((sum, s) => sum + s.count, 0);

  if (total === 0) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base font-medium flex items-center gap-2">
            <Server className="h-4 w-4 text-muted-foreground" />
            Alert Sources
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <p className="text-sm text-muted-foreground">No source data for selected range.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base font-medium flex items-center gap-2">
          <Server className="h-4 w-4 text-muted-foreground" />
          Alert Sources
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-0 space-y-3">
        {sources.map((item) => {
          const pct = total > 0 ? Math.round((item.count / total) * 100) : 0;
          const color = SOURCE_COLORS[item.source] ?? "bg-chart-5";
          const label = SOURCE_LABELS[item.source] ?? item.source;
          return (
            <div
              key={item.source}
              className="group cursor-pointer"
              onClick={() => router.push(`/alerts?source=${encodeURIComponent(item.source)}`)}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium">{label}</span>
                <span className="text-xs text-muted-foreground">
                  {item.count.toLocaleString()} ({pct}%)
                </span>
              </div>
              <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                <div
                  className={cn("h-full rounded-full transition-all duration-500", color)}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          );
        })}
        {data?.runtime_excluded && Object.keys(data.runtime_excluded).length > 0 && (
          <div className="pt-1 border-t border-border/50">
            <p className="text-xs text-muted-foreground">
              Runtime handled separately:{" "}
              {Object.entries(data.runtime_excluded)
                .map(([k, v]) => `${k} ${v}`)
                .join(", ")}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
