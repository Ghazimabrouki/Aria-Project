"use client";

import {
  CheckCircle2,
  AlertTriangle,
  Info,
  Lightbulb,
  Microscope,
  ShieldCheck,
  Clock,
  Check,
  Activity,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { DiagnosticFindings } from "@/lib/api";

interface DiagnosticFindingsProps {
  findings: DiagnosticFindings | null;
}

function ConfidenceBadge({ confidence }: { confidence: number }) {
  let label = "Low";
  let color = "text-red-600 bg-red-50 border-red-200";
  if (confidence >= 0.9) {
    label = "Very High";
    color = "text-emerald-700 bg-emerald-50 border-emerald-200";
  } else if (confidence >= 0.7) {
    label = "High";
    color = "text-emerald-700 bg-emerald-50 border-emerald-200";
  } else if (confidence >= 0.4) {
    label = "Medium";
    color = "text-amber-700 bg-amber-50 border-amber-200";
  }
  return (
    <span className={cn("text-xs font-medium px-2 py-0.5 rounded border", color)}>
      Confidence: {label}
    </span>
  );
}

function StatusLine({ findings }: { findings: DiagnosticFindings }) {
  if (!findings.requires_action && findings.is_temporary) {
    return (
      <div className="flex items-center gap-2 text-sm text-emerald-700">
        <CheckCircle2 className="h-4 w-4" />
        <span>Spike has subsided — no action required</span>
      </div>
    );
  }
  if (findings.requires_action) {
    return (
      <div className="flex items-center gap-2 text-sm text-red-700">
        <AlertTriangle className="h-4 w-4" />
        <span>Active anomaly detected — action recommended</span>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-2 text-sm text-blue-700">
      <Info className="h-4 w-4" />
      <span>Under observation</span>
    </div>
  );
}

export function DiagnosticFindingsCard({ findings }: DiagnosticFindingsProps) {
  if (!findings) {
    return (
      <Card className="border-dashed">
        <CardContent className="p-6 text-center text-muted-foreground">
          <Microscope className="mx-auto h-8 w-8 mb-2 opacity-50" />
          <p>Diagnostic findings will appear here once the investigation completes.</p>
        </CardContent>
      </Card>
    );
  }

  const hasRecommendations = findings.recommendations && findings.recommendations.length > 0;

  return (
    <div className="space-y-4">
      {/* Expert Summary */}
      <Card className={cn(
        "border-l-4",
        findings.requires_action ? "border-l-red-500" : findings.is_temporary ? "border-l-emerald-500" : "border-l-primary"
      )}>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <Microscope className="h-5 w-5 text-primary" />
              Expert Summary
            </CardTitle>
            <ConfidenceBadge confidence={findings.confidence} />
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm leading-relaxed">{findings.expert_summary}</p>
          <StatusLine findings={findings} />
        </CardContent>
      </Card>

      {/* Detected Cause & Impact */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Lightbulb className="h-4 w-4 text-amber-500" />
              Detected Cause
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm">{findings.detected_cause}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Activity className="h-4 w-4 text-orange-500" />
              Impact
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm">{findings.impact}</p>
          </CardContent>
        </Card>
      </div>

      {/* Technical Explanation */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Info className="h-4 w-4 text-blue-500" />
            Technical Explanation
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-sm whitespace-pre-wrap leading-relaxed">
            {findings.technical_explanation}
          </div>
        </CardContent>
      </Card>

      {/* Evidence */}
      {findings.evidence && findings.evidence.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Microscope className="h-4 w-4 text-purple-500" />
              Evidence ({findings.evidence.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {findings.evidence.map((item, idx) => (
                <div
                  key={idx}
                  className="rounded-lg border p-3 text-sm bg-muted/30"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium text-xs text-muted-foreground uppercase tracking-wide">
                      {item.source}
                    </span>
                    {item.timestamp && (
                      <span className="text-xs text-muted-foreground flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {item.timestamp}
                      </span>
                    )}
                  </div>
                  <p className="text-sm">{item.finding}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Recommendations */}
      {hasRecommendations && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-emerald-500" />
              Expert Recommendations
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {findings.recommendations.map((rec, idx) => (
                <div
                  key={idx}
                  className={cn(
                    "rounded-lg border p-3 text-sm",
                    rec.priority === 1 && "border-l-4 border-l-red-500 bg-red-50/30",
                    rec.priority === 2 && "border-l-4 border-l-amber-500 bg-amber-50/30",
                    rec.priority >= 3 && "border-l-4 border-l-blue-500 bg-blue-50/30"
                  )}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className={cn(
                      "text-xs font-bold px-1.5 py-0.5 rounded",
                      rec.priority === 1 && "bg-red-100 text-red-700",
                      rec.priority === 2 && "bg-amber-100 text-amber-700",
                      rec.priority >= 3 && "bg-blue-100 text-blue-700"
                    )}>
                      P{rec.priority}
                    </span>
                    <span className="font-medium">{rec.action}</span>
                  </div>
                  {rec.rationale && (
                    <p className="text-xs text-muted-foreground">{rec.rationale}</p>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
