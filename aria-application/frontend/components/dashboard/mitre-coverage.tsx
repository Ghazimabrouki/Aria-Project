"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { MitreCoverage } from "@/lib/api";
import { useRouter } from "next/navigation";
import { Shield } from "lucide-react";

interface MitreCoverageWidgetProps {
  data?: MitreCoverage;
  error?: boolean;
}

const TACTIC_COLORS: Record<string, string> = {
  "Initial Access": "bg-chart-1",
  Execution: "bg-chart-2",
  Persistence: "bg-chart-3",
  "Privilege Escalation": "bg-chart-4",
  "Defense Evasion": "bg-chart-5",
  "Credential Access": "bg-chart-1",
  Discovery: "bg-chart-2",
  "Lateral Movement": "bg-chart-3",
  Collection: "bg-chart-4",
  "Command and Control": "bg-chart-5",
  Exfiltration: "bg-destructive",
  Impact: "bg-destructive",
};

export function MitreCoverageWidget({ data, error }: MitreCoverageWidgetProps) {
  const router = useRouter();

  if (error) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base font-medium flex items-center gap-2">
            <Shield className="h-4 w-4 text-muted-foreground" />
            MITRE ATT&CK Coverage
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <p className="text-sm text-muted-foreground">Unable to load MITRE coverage.</p>
        </CardContent>
      </Card>
    );
  }

  const tactics = data?.tactics ?? [];
  const total = tactics.reduce((sum, t) => sum + t.count, 0);

  if (total === 0) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base font-medium flex items-center gap-2">
            <Shield className="h-4 w-4 text-muted-foreground" />
            MITRE ATT&CK Coverage
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <p className="text-sm text-muted-foreground">No MITRE ATT&CK data available for selected range.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base font-medium flex items-center gap-2">
          <Shield className="h-4 w-4 text-muted-foreground" />
          MITRE ATT&CK Coverage
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-0 space-y-3">
        {tactics.slice(0, 6).map((tactic) => {
          const pct = total > 0 ? Math.round((tactic.count / total) * 100) : 0;
          const color = TACTIC_COLORS[tactic.tactic] ?? "bg-primary";
          return (
            <div key={tactic.tactic} className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">{tactic.tactic}</span>
                <span className="text-xs text-muted-foreground">
                  {tactic.count.toLocaleString()} ({pct}%)
                </span>
              </div>
              <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                <div className={cn("h-full rounded-full transition-all duration-500", color)} style={{ width: `${pct}%` }} />
              </div>
              {tactic.techniques.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {tactic.techniques.slice(0, 4).map((tech) => (
                    <button
                      key={tech.technique}
                      onClick={() => {
                        if (tech.technique_id) {
                          router.push(`/alerts?mitre_technique=${encodeURIComponent(tech.technique_id)}`);
                        } else {
                          router.push(`/alerts?tactic=${encodeURIComponent(tactic.tactic)}`);
                        }
                      }}
                      className="inline-flex items-center rounded-md bg-muted px-1.5 py-0.5 text-xs text-muted-foreground hover:bg-muted/80 hover:text-foreground transition-colors cursor-pointer"
                      title={tech.technique_id ? `${tech.technique_id}: ${tech.technique}` : tech.technique}
                    >
                      {tech.technique_id ? `${tech.technique_id} ` : ""}
                      {tech.count}
                    </button>
                  ))}
                  {tactic.techniques.length > 4 && (
                    <span className="inline-flex items-center rounded-md bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
                      +{tactic.techniques.length - 4}
                    </span>
                  )}
                </div>
              )}
            </div>
          );
        })}
        {tactics.length > 6 && (
          <p className="text-xs text-muted-foreground pt-1">
            +{tactics.length - 6} more tactics
          </p>
        )}
      </CardContent>
    </Card>
  );
}
