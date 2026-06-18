"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ResponseMetrics } from "@/lib/api";
import { Clock, Zap, TrendingUp } from "lucide-react";

interface ResponseMetricsWidgetProps {
  data?: ResponseMetrics;
  error?: boolean;
}

function fmtDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) {
    const h = Math.floor(seconds / 3600);
    const m = Math.round((seconds % 3600) / 60);
    return m > 0 ? `${h}h ${m}m` : `${h}h`;
  }
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  return h > 0 ? `${d}d ${h}h` : `${d}d`;
}

export function ResponseMetricsWidget({ data, error }: ResponseMetricsWidgetProps) {
  if (error) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base font-medium flex items-center gap-2">
            <Clock className="h-4 w-4 text-muted-foreground" />
            Response Metrics
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <p className="text-sm text-muted-foreground">Unable to load response metrics.</p>
        </CardContent>
      </Card>
    );
  }

  const mttd = data?.mttd_seconds;
  const mttr = data?.mttr_seconds;
  const opMttr = data?.operational_mttr_seconds;
  const mttdSample = data?.sample_size?.mttd ?? 0;
  const mttrSample = data?.sample_size?.mttr ?? 0;
  const opMttrSample = data?.sample_size?.operational_mttr ?? 0;

  const hasData = mttdSample > 0 || mttrSample > 0 || opMttrSample > 0;

  if (!hasData) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base font-medium flex items-center gap-2">
            <Clock className="h-4 w-4 text-muted-foreground" />
            Response Metrics
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <p className="text-sm text-muted-foreground">Not enough resolved incident data yet.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <CardTitle className="text-base font-medium flex items-center gap-2">
          <Clock className="h-4 w-4 text-muted-foreground" />
          Response Metrics
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-lg border bg-muted/30 p-3 space-y-1">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Zap className="h-3.5 w-3.5" />
              <span className="text-xs font-semibold uppercase tracking-wider">MTTD</span>
            </div>
            <p className="text-xl font-bold tracking-tight">{fmtDuration(mttd)}</p>
            <p className="text-xs text-muted-foreground">
              {mttdSample > 0 ? `n=${mttdSample}` : "No data"}
            </p>
          </div>
          <div className="rounded-lg border bg-muted/30 p-3 space-y-1">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Clock className="h-3.5 w-3.5" />
              <span className="text-xs font-semibold uppercase tracking-wider">MTTR</span>
            </div>
            <p className="text-xl font-bold tracking-tight">{fmtDuration(mttr)}</p>
            <p className="text-xs text-muted-foreground">
              {mttrSample > 0 ? `n=${mttrSample}` : "No data"}
            </p>
          </div>
        </div>

        {opMttrSample > 0 && (
          <div className="mt-3 rounded-lg border border-primary/20 bg-primary/5 p-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-muted-foreground">
                <TrendingUp className="h-3.5 w-3.5 text-primary" />
                <span className="text-xs font-semibold uppercase tracking-wider">Operational MTTR</span>
              </div>
              <span className="text-base font-bold">{fmtDuration(opMttr)}</span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              n={opMttrSample} incidents (first investigation completed)
            </p>
          </div>
        )}

        {data?.notes && data.notes.length > 0 && (
          <div className="mt-3 pt-2 border-t border-border/50">
            {data.notes.map((note, i) => (
              <p key={i} className="text-xs text-muted-foreground">{note}</p>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
