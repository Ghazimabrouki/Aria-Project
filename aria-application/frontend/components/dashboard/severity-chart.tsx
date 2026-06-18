"use client";

import { useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import type { SeverityCount } from "@/lib/api";

interface SeverityChartProps {
  data: SeverityCount[];
  onSliceClick?: (severity: string) => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

export function SeverityChart({ data, onSliceClick }: SeverityChartProps) {
  const chartData = useMemo(() => {
    // Merge incoming data with base severity set so every level is always visible
    const merged = new Map<string, number>();
    for (const s of SEVERITY_ORDER) merged.set(s, 0);
    for (const item of data) merged.set(item.severity, item.count);

    return SEVERITY_ORDER.map((severity) => ({
      name: severity.charAt(0).toUpperCase() + severity.slice(1),
      value: merged.get(severity) || 0,
      color: SEVERITY_COLORS[severity] || "#6b7280",
      severity,
    }));
  }, [data]);

  const total = useMemo(() => chartData.reduce((sum, item) => sum + item.value, 0), [chartData]);

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base font-medium">Incidents by Severity</CardTitle>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="h-[280px] relative">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="45%"
                innerRadius={55}
                outerRadius={85}
                paddingAngle={3}
                dataKey="value"
                animationBegin={0}
                animationDuration={800}
                animationEasing="ease-out"
                onClick={(_, index) => {
                  const severity = chartData[index]?.severity;
                  if (severity && onSliceClick) onSliceClick(severity);
                }}
                cursor={onSliceClick ? "pointer" : "default"}
              >
                {chartData.map((entry, index) => (
                  <Cell 
                    key={`cell-${index}`} 
                    fill={entry.color}
                    stroke="transparent"
                    style={{
                      filter: `drop-shadow(0 0 6px ${entry.color}40)`,
                    }}
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "var(--color-popover)",
                  border: "1px solid var(--color-border)",
                  borderRadius: "8px",
                  color: "var(--color-popover-foreground)",
                  boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
                }}
                formatter={(value: number, name: string) => [
                  <span key="value" className="font-mono">{value.toLocaleString()}</span>,
                  <span key="name" className="font-medium">{name}</span>
                ]}
              />
            </PieChart>
          </ResponsiveContainer>
          
          {/* Center text */}
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none" style={{ marginTop: "-20px" }}>
            <div className="text-center">
              <span className="text-2xl font-bold">{total.toLocaleString()}</span>
              <p className="text-xs text-muted-foreground">Total</p>
            </div>
          </div>
        </div>
        
        {/* Custom legend */}
        <div className="flex items-center justify-center gap-4 mt-2">
          {chartData.map((item) => (
            <div key={item.severity} className="flex items-center gap-1.5">
              <div 
                className="w-3 h-3 rounded-full" 
                style={{ backgroundColor: item.color }}
              />
              <span className="text-xs text-muted-foreground">{item.name}</span>
              <span className="text-xs font-mono font-medium">{item.value}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
