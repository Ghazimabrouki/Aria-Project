"use client";

import { useState } from "react";
import { ShieldAlert, AlertTriangle, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { runtimeAPI, type RuntimeInvestigation } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";

interface ManualRemediationApproveModalProps {
  investigation: RuntimeInvestigation;
  onClose: () => void;
  onMutate: () => void;
}

export function ManualRemediationApproveModal({ investigation, onClose, onMutate }: ManualRemediationApproveModalProps) {
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [confirmationText, setConfirmationText] = useState("");
  const [checkedRollback, setCheckedRollback] = useState(false);
  const [checkedScope, setCheckedScope] = useState(false);

  const manualOverride = investigation.manual_override_json || {};
  const riskLevel = manualOverride.risk_level || "unknown";
  const isHighRisk = riskLevel === "high" || riskLevel === "critical";
  const adminReason = manualOverride.admin_reason || "";
  const expectedImpact = manualOverride.expected_impact || "";

  const canApprove =
    confirmationText === "I UNDERSTAND THE RISK" &&
    (!isHighRisk || (checkedRollback && checkedScope));

  const handleApprove = async () => {
    if (!canApprove) {
      toast({ title: "Confirmation required", description: "Please complete all confirmations.", variant: "destructive" });
      return;
    }
    setLoading(true);
    try {
      await runtimeAPI.manualRemediation.approveRun(investigation.id, confirmationText);
      toast({ title: "Approved", description: "Manual remediation approved and execution started." });
      onMutate();
      onClose();
    } catch (err: any) {
      toast({ title: "Error", description: err?.message || "Failed to approve.", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-md rounded-lg border bg-card p-6 shadow-lg">
        <h3 className="text-lg font-semibold flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-amber-500" />
          Approve Manual Remediation
        </h3>

        <div className="mt-3 space-y-3">
          <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm dark:border-amber-800 dark:bg-amber-950/10">
            <div className="font-medium text-amber-700 dark:text-amber-400 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Warning: You are overriding the system planner
            </div>
            <p className="mt-1 text-xs text-amber-600 dark:text-amber-300">
              The automated planner did not recommend this remediation. You are taking full responsibility for the outcome.
            </p>
          </div>

          <div className="text-sm space-y-1">
            <div><span className="font-medium">Risk level:</span> <Badge variant={isHighRisk ? "destructive" : "secondary"}>{riskLevel}</Badge></div>
            <div><span className="font-medium">Admin reason:</span> {adminReason}</div>
            <div><span className="font-medium">Expected impact:</span> {expectedImpact}</div>
          </div>

          {isHighRisk && (
            <div className="space-y-2">
              <label className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={checkedRollback}
                  onChange={(e) => setCheckedRollback(e.target.checked)}
                />
                <span>I have reviewed the rollback plan and understand how to reverse this change.</span>
              </label>
              <label className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={checkedScope}
                  onChange={(e) => setCheckedScope(e.target.checked)}
                />
                <span>I have verified the target scope and confirmed this will not affect unintended systems.</span>
              </label>
            </div>
          )}

          <div>
            <label className="text-sm font-medium">
              Type <code className="bg-muted px-1 rounded">I UNDERSTAND THE RISK</code> to confirm
            </label>
            <input
              className="mt-1 w-full rounded-md border bg-background px-3 py-2 text-sm"
              placeholder="I UNDERSTAND THE RISK"
              value={confirmationText}
              onChange={(e) => setConfirmationText(e.target.value)}
            />
          </div>
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <Button variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          <Button variant="default" size="sm" onClick={handleApprove} disabled={loading || !canApprove} className="gap-1.5">
            <CheckCircle2 className="h-4 w-4" />
            Approve & Run
          </Button>
        </div>
      </div>
    </div>
  );
}
