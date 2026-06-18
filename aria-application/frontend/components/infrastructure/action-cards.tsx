"use client";

import { Shield, RotateCcw, CheckCircle2, AlertTriangle, Info } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export interface SuggestedAction {
  action: string;
  risk: string;
  expected_outcome: string;
  system_impact: string;
  rollback_feasible: boolean;
}

interface ActionCardsProps {
  actions: SuggestedAction[];
}

function RiskBadge({ risk }: { risk: string }) {
  const level = risk?.toLowerCase() || "";
  const isLow = level.includes("low");
  const isMedium = level.includes("medium");
  const isHigh = level.includes("high");

  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-1 font-medium",
        isLow && "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
        isMedium && "bg-amber-500/10 text-amber-500 border-amber-500/20",
        isHigh && "bg-destructive/10 text-destructive border-destructive/20"
      )}
    >
      {isLow && <CheckCircle2 className="h-3 w-3" />}
      {isMedium && <AlertTriangle className="h-3 w-3" />}
      {isHigh && <AlertTriangle className="h-3 w-3" />}
      {risk}
    </Badge>
  );
}

export function ActionCards({ actions }: ActionCardsProps) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <Shield className="h-4 w-4 text-primary" />
          Suggested Remediation Actions
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {actions.map((action, idx) => (
          <div
            key={idx}
            className="rounded-lg border bg-card p-4 space-y-3 hover:shadow-sm transition-shadow"
          >
            {/* Header */}
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary">
                  {idx + 1}
                </span>
                <span className="font-medium text-sm">{action.action}</span>
              </div>
              <RiskBadge risk={action.risk} />
            </div>

            {/* Details grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
              <div className="space-y-1">
                <div className="flex items-center gap-1.5 text-muted-foreground text-xs">
                  <CheckCircle2 className="h-3 w-3" />
                  Expected Outcome
                </div>
                <p className="text-sm">{action.expected_outcome}</p>
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-1.5 text-muted-foreground text-xs">
                  <Info className="h-3 w-3" />
                  System Impact
                </div>
                <p className="text-sm">{action.system_impact}</p>
              </div>
            </div>

            {/* Footer */}
            <div className="flex items-center gap-2 pt-1 border-t">
              <RotateCcw className="h-3 w-3 text-muted-foreground" />
              <span className="text-xs text-muted-foreground">
                Rollback:{" "}
                <span
                  className={cn(
                    "font-medium",
                    action.rollback_feasible ? "text-emerald-500" : "text-destructive"
                  )}
                >
                  {action.rollback_feasible ? "Feasible" : "Not feasible"}
                </span>
              </span>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
