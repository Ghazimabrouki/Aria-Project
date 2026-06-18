"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { GeoThreats, GeoThreatPoint } from "@/lib/api";
import { Globe, MapPin, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
} from "react-simple-maps";

interface GeoThreatWidgetProps {
  data?: GeoThreats;
  error?: boolean;
}

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

const severityColors: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

function getDominantSeverity(breakdown: GeoThreatPoint["severity_breakdown"]): string {
  const entries = Object.entries(breakdown).sort((a, b) => b[1] - a[1]);
  return entries[0]?.[1] > 0 ? entries[0][0] : "low";
}

export function GeoThreatWidget({ data, error }: GeoThreatWidgetProps) {
  if (error) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base font-medium flex items-center gap-2">
            <Globe className="h-4 w-4 text-muted-foreground" />
            Geographic Threats
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <p className="text-sm text-muted-foreground">Unable to load geographic threat data.</p>
        </CardContent>
      </Card>
    );
  }

  const points = data?.points ?? [];

  if (points.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base font-medium flex items-center gap-2">
            <Globe className="h-4 w-4 text-muted-foreground" />
            Geographic Threats
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <p className="text-sm text-muted-foreground">No geographic threat data available for selected range.</p>
          {(data?.unresolved_count ?? 0) > 0 && (
            <p className="text-xs text-muted-foreground mt-1">
              {data?.unresolved_count} alerts without valid geo coordinates.
            </p>
          )}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="h-full flex flex-col">
      <CardHeader className="pb-2 shrink-0">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base font-medium flex items-center gap-2">
            <Globe className="h-4 w-4 text-primary" />
            Geographic Threats
          </CardTitle>
          <Badge variant="secondary" className="text-xs font-normal">
            {points.length} location{points.length > 1 ? "s" : ""}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="pt-0 space-y-3 flex-1 flex flex-col min-h-0">
        {/* Map */}
        <div className="rounded-lg border bg-muted/30 overflow-hidden shrink-0" style={{ height: 200 }}>
          <ComposableMap projection="geoEqualEarth" projectionConfig={{ scale: 130 }} style={{ width: "100%", height: "100%" }}>
            <Geographies geography={geoUrl}>
              {({ geographies }: { geographies: Array<{ rsmKey: string; properties: Record<string, unknown> }> }) =>
                geographies.map((geo) => (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo as unknown as object}
                    fill="hsl(var(--muted))"
                    stroke="hsl(var(--border))"
                    strokeWidth={0.5}
                    style={{ default: { outline: "none" }, hover: { outline: "none" }, pressed: { outline: "none" } }}
                  />
                ))
              }
            </Geographies>
            {points.map((pt, i) => {
              const dominant = getDominantSeverity(pt.severity_breakdown);
              const color = severityColors[dominant] || severityColors.low;
              const r = Math.min(3 + pt.count * 0.6, 10);
              return (
                <Marker key={i} coordinates={[pt.longitude, pt.latitude]}>
                  <circle r={r} fill={color} fillOpacity={0.75} stroke="hsl(var(--background))" strokeWidth={1.5} />
                </Marker>
              );
            })}
          </ComposableMap>
        </div>

        {/* Ranked List */}
        <div className="space-y-1.5 flex-1 overflow-auto">
          {points.slice(0, 5).map((pt, i) => {
            const dominant = getDominantSeverity(pt.severity_breakdown);
            const color = severityColors[dominant] || severityColors.low;
            return (
              <div key={i} className="flex items-center justify-between text-sm py-1">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-xs text-muted-foreground font-mono w-4">{i + 1}</span>
                  <MapPin className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  <span className="truncate">
                    {pt.city ? `${pt.city}, ` : ""}
                    {pt.country}
                  </span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-xs font-medium tabular-nums">{pt.count}</span>
                  <span className="inline-block h-2 w-2 rounded-full shrink-0" style={{ backgroundColor: color }} />
                </div>
              </div>
            );
          })}
        </div>

        {(data?.unresolved_count ?? 0) > 0 && (
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground/80 shrink-0 pt-1 border-t border-border/30">
            <ShieldAlert className="h-3 w-3" />
            {data?.unresolved_count} alerts without valid geo coordinates
          </div>
        )}
      </CardContent>
    </Card>
  );
}
