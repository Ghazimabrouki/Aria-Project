"use client";

import { Terminal } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface ProcessInfo {
  name: string;
  pid: number;
  cpu_percent?: number;
  memory_rss?: number;
  memory_percent?: number;
  cmdline?: string;
}

interface ProcessTableProps {
  processes: ProcessInfo[];
  highlightPid?: number;
  maxRows?: number;
}

function MiniBar({ value, max = 100, colorClass }: { value?: number; max?: number; colorClass: string }) {
  const pct = Math.min(100, Math.max(0, ((value ?? 0) / max) * 100));
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 rounded-full bg-muted overflow-hidden flex-shrink-0">
        <div
          className={cn("h-full rounded-full transition-all", colorClass)}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs tabular-nums w-10 text-right">{value?.toFixed(1) ?? "—"}%</span>
    </div>
  );
}

export function ProcessTable({ processes, highlightPid, maxRows = 10 }: ProcessTableProps) {
  const display = processes.slice(0, maxRows);
  const maxCpu = Math.max(1, ...display.map((p) => p.cpu_percent ?? 0));
  const maxMem = Math.max(1, ...display.map((p) => p.memory_percent ?? 0));

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <Terminal className="h-4 w-4 text-primary" />
          Top Processes
          {highlightPid && (
            <span className="text-xs font-normal text-muted-foreground ml-2">
              (highlighted = responsible)
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-muted-foreground text-xs uppercase tracking-wider">
                <th className="text-left py-2 px-3 font-medium">Process</th>
                <th className="text-left py-2 px-3 font-medium">PID</th>
                <th className="text-left py-2 px-3 font-medium">CPU</th>
                <th className="text-left py-2 px-3 font-medium">Memory</th>
              </tr>
            </thead>
            <tbody>
              {display.map((proc, idx) => {
                const isHighlighted = highlightPid && proc.pid === highlightPid;
                return (
                  <tr
                    key={idx}
                    className={cn(
                      "border-b last:border-b-0 transition-colors",
                      isHighlighted
                        ? "bg-primary/5 hover:bg-primary/10"
                        : "hover:bg-accent/50"
                    )}
                  >
                    <td className="py-2 px-3">
                      <div className="flex flex-col">
                        <span className={cn("font-medium", isHighlighted && "text-primary")}>
                          {proc.name}
                          {isHighlighted && (
                            <span className="ml-1.5 text-xs uppercase tracking-wide text-primary/70 font-semibold">
                              responsible
                            </span>
                          )}
                        </span>
                        {proc.cmdline && (
                          <span className="text-xs text-muted-foreground truncate max-w-[240px]">
                            {proc.cmdline}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-2 px-3">
                      <span className="font-mono text-muted-foreground text-xs">{proc.pid}</span>
                    </td>
                    <td className="py-2 px-3">
                      <MiniBar
                        value={proc.cpu_percent}
                        max={maxCpu}
                        colorClass={isHighlighted ? "bg-primary" : "bg-blue-500"}
                      />
                    </td>
                    <td className="py-2 px-3">
                      <MiniBar
                        value={proc.memory_percent}
                        max={maxMem}
                        colorClass={isHighlighted ? "bg-primary" : "bg-purple-500"}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}
