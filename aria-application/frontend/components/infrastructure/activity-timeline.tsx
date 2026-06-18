"use client";

import { Clock, CheckCircle2, XCircle, Play, Archive, AlertTriangle, User, Activity } from "lucide-react";
import { formatDistanceToNow, format } from "date-fns";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface TimelineEvent {
  id: string;
  timestamp: string;
  type: "created" | "approved" | "declined" | "running" | "completed" | "failed" | "archived" | "acknowledged" | "escalated" | "diagnosed";
  actor?: string;
  detail?: string;
}

interface ActivityTimelineProps {
  events: TimelineEvent[];
}

const eventConfig: Record<string, { icon: React.ElementType; label: string; color: string }> = {
  created: { icon: AlertTriangle, label: "Investigation Created", color: "text-primary bg-primary/10" },
  approved: { icon: CheckCircle2, label: "Remediation Approved", color: "text-emerald-500 bg-emerald-500/10" },
  declined: { icon: XCircle, label: "Remediation Declined", color: "text-destructive bg-destructive/10" },
  running: { icon: Play, label: "Playbook Executing", color: "text-blue-500 bg-blue-500/10" },
  completed: { icon: CheckCircle2, label: "Execution Completed", color: "text-emerald-500 bg-emerald-500/10" },
  failed: { icon: XCircle, label: "Execution Failed", color: "text-destructive bg-destructive/10" },
  archived: { icon: Archive, label: "Investigation Archived", color: "text-muted-foreground bg-muted" },
  acknowledged: { icon: CheckCircle2, label: "Acknowledged", color: "text-emerald-600 bg-emerald-600/10" },
  escalated: { icon: AlertTriangle, label: "Escalated", color: "text-amber-500 bg-amber-500/10" },
  diagnosed: { icon: Activity, label: "Diagnosis Triggered", color: "text-cyan-500 bg-cyan-500/10" },
};

export function ActivityTimeline({ events }: ActivityTimelineProps) {
  if (!events.length) return null;

  const sorted = [...events].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <Clock className="h-4 w-4 text-primary" />
          Activity Timeline
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="relative pl-4">
          {/* Vertical line */}
          <div className="absolute left-[19px] top-2 bottom-2 w-px bg-border" />

          <div className="space-y-4">
            {sorted.map((event) => {
              const config = eventConfig[event.type] || eventConfig.created;
              const Icon = config.icon;
              return (
                <div key={event.id} className="relative flex items-start gap-3">
                  <div
                    className={cn(
                      "relative z-10 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border",
                      config.color
                    )}
                  >
                    <Icon className="h-3.5 w-3.5" />
                  </div>
                  <div className="flex-1 space-y-0.5 pb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{config.label}</span>
                      <span className="text-xs text-muted-foreground">
                        {formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}
                      </span>
                    </div>
                    {event.actor && (
                      <div className="flex items-center gap-1 text-xs text-muted-foreground">
                        <User className="h-3 w-3" />
                        {event.actor}
                      </div>
                    )}
                    {event.detail && (
                      <p className="text-xs text-muted-foreground">{event.detail}</p>
                    )}
                    <p className="text-xs text-muted-foreground tabular-nums">
                      {format(new Date(event.timestamp), "MMM d, yyyy HH:mm:ss")}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
