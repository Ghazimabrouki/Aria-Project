"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/status-badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  CheckCircle2,
  XCircle,
  Play,
  Clock,
  ChevronRight,
  AlertTriangle,
  Terminal,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { Playbook, PlaybookStep } from "@/lib/api";

interface PlaybookViewerProps {
  playbook: Playbook;
  canApprove?: boolean;
  canExecute?: boolean;
  onApprove?: () => void;
  onDecline?: (reason: string) => void;
  onExecute?: () => void;
  isLoading?: boolean;
}

const stepIcons: Record<string, React.ElementType> = {
  pending: Clock,
  running: Play,
  completed: CheckCircle2,
  failed: XCircle,
  skipped: ChevronRight,
};

export function PlaybookViewer({
  playbook,
  canApprove,
  canExecute,
  onApprove,
  onDecline,
  onExecute,
  isLoading,
}: PlaybookViewerProps) {
  const [showDeclineDialog, setShowDeclineDialog] = useState(false);
  const [declineReason, setDeclineReason] = useState("");

  const handleDecline = () => {
    onDecline?.(declineReason);
    setShowDeclineDialog(false);
    setDeclineReason("");
  };

  return (
    <>
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <CardTitle className="text-base font-medium">
                {playbook.name}
              </CardTitle>
              <p className="text-sm text-muted-foreground">
                {playbook.description}
              </p>
            </div>
            <StatusBadge status={playbook.status} />
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Steps */}
          <div className="space-y-3">
            <h4 className="text-sm font-medium text-muted-foreground">
              Playbook Steps ({playbook.steps.length})
            </h4>
            <ScrollArea className="h-[300px] pr-4">
              <div className="space-y-2">
                {playbook.steps.map((step, index) => (
                  <PlaybookStepCard
                    key={step.id}
                    step={step}
                    index={index}
                    isLast={index === playbook.steps.length - 1}
                  />
                ))}
              </div>
            </ScrollArea>
          </div>

          {/* Actions */}
          {(canApprove || canExecute) && (
            <div className="flex items-center justify-end gap-3 border-t pt-4">
              {canApprove && (
                <>
                  <Button
                    variant="outline"
                    onClick={() => setShowDeclineDialog(true)}
                    disabled={isLoading}
                  >
                    <XCircle className="mr-2 h-4 w-4" />
                    Decline
                  </Button>
                  <Button onClick={onApprove} disabled={isLoading}>
                    <CheckCircle2 className="mr-2 h-4 w-4" />
                    Approve Playbook
                  </Button>
                </>
              )}
              {canExecute && (
                <Button onClick={onExecute} disabled={isLoading}>
                  <Play className="mr-2 h-4 w-4" />
                  Execute Playbook
                </Button>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Decline Dialog */}
      <Dialog open={showDeclineDialog} onOpenChange={setShowDeclineDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Decline Playbook</DialogTitle>
            <DialogDescription>
              Please provide a reason for declining this playbook. The investigation
              will require manual review.
            </DialogDescription>
          </DialogHeader>
          <Textarea
            placeholder="Enter reason for declining..."
            value={declineReason}
            onChange={(e) => setDeclineReason(e.target.value)}
            rows={4}
          />
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowDeclineDialog(false)}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDecline}
              disabled={!declineReason.trim()}
            >
              Decline Playbook
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function PlaybookStepCard({
  step,
  index,
  isLast,
}: {
  step: PlaybookStep;
  index: number;
  isLast: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const Icon = stepIcons[step.status] || Clock;

  return (
    <div className="relative">
      {/* Connector line */}
      {!isLast && (
        <div className="absolute left-5 top-12 h-[calc(100%-24px)] w-px bg-border" />
      )}

      <div
        className={cn(
          "rounded-lg border bg-card p-4 transition-all",
          step.status === "running" && "border-primary/50 bg-primary/5",
          step.status === "failed" && "border-destructive/50 bg-destructive/5",
          step.status === "completed" && "border-success/50 bg-success/5"
        )}
      >
        <div className="flex items-start gap-3">
          <div
            className={cn(
              "flex h-10 w-10 shrink-0 items-center justify-center rounded-lg",
              step.status === "pending" && "bg-muted text-muted-foreground",
              step.status === "running" && "bg-primary/10 text-primary",
              step.status === "completed" && "bg-success/10 text-success",
              step.status === "failed" && "bg-destructive/10 text-destructive",
              step.status === "skipped" && "bg-muted text-muted-foreground"
            )}
          >
            {step.status === "running" ? (
              <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            ) : (
              <Icon className="h-5 w-5" />
            )}
          </div>

          <div className="flex-1 space-y-1">
            <div className="flex items-center justify-between">
              <p className="font-medium">
                Step {index + 1}: {step.action}
              </p>
              <StatusBadge status={step.status} />
            </div>
            <p className="text-sm text-muted-foreground">{step.description}</p>

            {step.output && (
              <div className="mt-3">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-auto p-0 text-xs text-muted-foreground"
                  onClick={() => setExpanded(!expanded)}
                >
                  <Terminal className="mr-1 h-3 w-3" />
                  {expanded ? "Hide Output" : "Show Output"}
                </Button>
                {expanded && (
                  <pre className="mt-2 max-h-40 overflow-auto rounded-lg bg-muted p-3 font-mono text-xs">
                    {step.output}
                  </pre>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
