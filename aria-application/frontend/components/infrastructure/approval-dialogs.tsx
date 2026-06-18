"use client";

import { useState } from "react";
import { Shield, ThumbsUp, ThumbsDown, AlertTriangle, CheckCircle2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import type { SuggestedAction } from "./action-cards";

interface ApproveDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  actions: SuggestedAction[];
  onApprove: (acknowledgeRisk: boolean) => void;
  loading?: boolean;
}

export function ApproveDialog({ open, onOpenChange, actions, onApprove, loading }: ApproveDialogProps) {
  const [acknowledged, setAcknowledged] = useState(false);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            Approve Infrastructure Remediation
          </DialogTitle>
          <DialogDescription>
            Review the risk assessment before approving this remediation action.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          {/* Risk cards */}
          <div className="space-y-2">
            {actions.map((action, idx) => {
              const isHigh = action.risk?.toLowerCase().includes("high");
              return (
                <div
                  key={idx}
                  className={cn(
                    "rounded-lg border p-3 space-y-2",
                    isHigh && "border-destructive/30 bg-destructive/5"
                  )}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">{action.action}</span>
                    <Badge
                      variant="outline"
                      className={cn(
                        action.risk?.toLowerCase().includes("low")
                          ? "bg-emerald-500/10 text-emerald-500"
                          : action.risk?.toLowerCase().includes("medium")
                          ? "bg-amber-500/10 text-amber-500"
                          : "bg-destructive/10 text-destructive"
                      )}
                    >
                      {action.risk}
                    </Badge>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Expected: {action.expected_outcome}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Acknowledge */}
          <div className="flex items-start gap-3 rounded-lg border p-3">
            <Checkbox
              id="acknowledge"
              checked={acknowledged}
              onCheckedChange={(v) => setAcknowledged(v === true)}
            />
            <div className="grid gap-1.5 leading-none">
              <Label htmlFor="acknowledge" className="text-sm font-medium cursor-pointer">
                I understand the risk and approve this remediation
              </Label>
              <p className="text-xs text-muted-foreground">
                This action will execute an Ansible playbook on the target host.
              </p>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => onApprove(acknowledged)}
            disabled={!acknowledged || loading}
            className="gap-2"
          >
            {loading ? (
              <>
                <div className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
                Approving...
              </>
            ) : (
              <>
                <ThumbsUp className="h-4 w-4" />
                Confirm Approval
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

interface DeclineDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDecline: (reason: string) => void;
  loading?: boolean;
}

export function DeclineDialog({ open, onOpenChange, onDecline, loading }: DeclineDialogProps) {
  const [reason, setReason] = useState("");

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-destructive">
            <ThumbsDown className="h-5 w-5" />
            Decline Remediation
          </DialogTitle>
          <DialogDescription>
            Provide a reason for declining this remediation action.
          </DialogDescription>
        </DialogHeader>

        <div className="py-2">
          <Label htmlFor="decline-reason" className="text-sm font-medium mb-2 block">
            Reason
          </Label>
          <Textarea
            id="decline-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="e.g., False positive, scheduled maintenance, manual handling..."
            className="min-h-[100px]"
          />
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={() => onDecline(reason)}
            disabled={loading}
            className="gap-2"
          >
            {loading ? (
              <>
                <div className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
                Declining...
              </>
            ) : (
              <>
                <ThumbsDown className="h-4 w-4" />
                Decline
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
