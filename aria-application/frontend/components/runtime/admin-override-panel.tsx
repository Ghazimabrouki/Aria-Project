"use client";

import { useState } from "react";
import {
  ShieldAlert,
  AlertTriangle,
  FileCode,
  CheckCircle2,
  RotateCcw,
  AlertOctagon,
  ThumbsDown,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { runtimeAPI, type RuntimeInvestigation } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import { ManualRemediationEditor } from "./manual-remediation-editor";
import { ManualRemediationApproveModal } from "./manual-remediation-approve-modal";

interface AdminOverridePanelProps {
  investigation: RuntimeInvestigation;
  onMutate: () => void;
}

export function AdminOverridePanel({ investigation, onMutate }: AdminOverridePanelProps) {
  const { toast } = useToast();
  const [actionLoading, setActionLoading] = useState(false);
  const [showEditor, setShowEditor] = useState(false);
  const [showApproveModal, setShowApproveModal] = useState(false);
  const [showForceDeclineModal, setShowForceDeclineModal] = useState(false);
  const [showReopenModal, setShowReopenModal] = useState(false);
  const [forceDeclineReason, setForceDeclineReason] = useState("");
  const [reopenReason, setReopenReason] = useState("");

  const availableActions = (investigation.available_actions || {}) as NonNullable<RuntimeInvestigation["available_actions"]>;
  const manualOverride = investigation.manual_override_json || {};
  const validationResult = manualOverride.validation_result || {};

  const handleForceDecline = async () => {
    if (!forceDeclineReason || forceDeclineReason.length < 10) {
      toast({ title: "Reason required", description: "Please provide a reason of at least 10 characters.", variant: "destructive" });
      return;
    }
    setActionLoading(true);
    try {
      await runtimeAPI.manualRemediation.forceDecline(investigation.id, forceDeclineReason);
      toast({ title: "Force Declined", description: "Investigation has been force-declined." });
      setShowForceDeclineModal(false);
      setForceDeclineReason("");
      onMutate();
    } catch (err: any) {
      toast({ title: "Error", description: err?.message || "Failed to force-decline.", variant: "destructive" });
    } finally {
      setActionLoading(false);
    }
  };

  const handleReopen = async () => {
    if (!reopenReason || reopenReason.length < 10) {
      toast({ title: "Reason required", description: "Please provide a reason of at least 10 characters.", variant: "destructive" });
      return;
    }
    setActionLoading(true);
    try {
      await runtimeAPI.manualRemediation.reopen(investigation.id, reopenReason);
      toast({ title: "Reopened", description: "Investigation has been reopened." });
      setShowReopenModal(false);
      setReopenReason("");
      onMutate();
    } catch (err: any) {
      toast({ title: "Error", description: err?.message || "Failed to reopen.", variant: "destructive" });
    } finally {
      setActionLoading(false);
    }
  };

  const handleValidate = async () => {
    setActionLoading(true);
    try {
      const result = await runtimeAPI.manualRemediation.validate(investigation.id);
      toast({
        title: result.valid ? "Validation Passed" : "Validation Failed",
        description: result.executable
          ? `Risk level: ${result.risk_level}. ${result.can_approve ? "Ready for approval." : "Cannot approve."}`
          : `Blocked: ${result.reasons?.join("; ") || "Unknown"}`,
        variant: result.valid ? "default" : "destructive",
      });
      onMutate();
    } catch (err: any) {
      toast({ title: "Error", description: err?.message || "Validation failed.", variant: "destructive" });
    } finally {
      setActionLoading(false);
    }
  };

  const showAnyAdminAction =
    availableActions.create_manual_remediation ||
    availableActions.edit_manual_playbook ||
    availableActions.validate_manual_playbook ||
    availableActions.approve_manual_remediation ||
    availableActions.force_decline ||
    availableActions.reopen;

  if (!showAnyAdminAction) return null;

  return (
    <>
      <Card className="border-amber-200 bg-amber-50/30 dark:border-amber-800 dark:bg-amber-950/10">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-amber-700 dark:text-amber-400">
            <ShieldAlert className="h-5 w-5" />
            Admin Override
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* System recommendation */}
          <Alert variant="default" className="bg-muted/50">
            <AlertTitle className="text-sm font-medium">System Recommendation</AlertTitle>
            <AlertDescription className="text-xs text-muted-foreground">
              {investigation.remediation_summary?.actual_remediation_available
                ? "Automatic remediation is available. Use normal Approve & Run if corrective actions exist."
                : investigation.outcome_summary?.message || "No automatic remediation available."}
            </AlertDescription>
          </Alert>

          {/* Why automatic is blocked */}
          {!investigation.remediation_summary?.actual_remediation_available && (
            <div className="text-xs text-muted-foreground">
              <span className="font-medium">Why automatic remediation is blocked:</span>{" "}
              {investigation.remediation_summary?.message || "The planner could not find a safe, evidence-backed action."}
            </div>
          )}

          {/* Action buttons */}
          <div className="flex flex-wrap gap-2">
            {availableActions.create_manual_remediation && (
              <Button variant="outline" size="sm" onClick={() => setShowEditor(true)} disabled={actionLoading} className="gap-1.5">
                <FileCode className="h-3.5 w-3.5" />
                Create Manual Remediation
              </Button>
            )}
            {(availableActions.edit_manual_playbook || availableActions.validate_manual_playbook) && (
              <>
                <Button variant="outline" size="sm" onClick={() => setShowEditor(true)} disabled={actionLoading} className="gap-1.5">
                  <FileCode className="h-3.5 w-3.5" />
                  Edit Playbook
                </Button>
                <Button variant="default" size="sm" onClick={handleValidate} disabled={actionLoading} className="gap-1.5">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  Validate
                </Button>
              </>
            )}
            {availableActions.approve_manual_remediation && (
              <Button variant="default" size="sm" onClick={() => setShowApproveModal(true)} disabled={actionLoading} className="gap-1.5">
                <ShieldAlert className="h-3.5 w-3.5" />
                Approve & Run Manual
              </Button>
            )}
            {availableActions.force_decline && (
              <Button variant="ghost" size="sm" onClick={() => setShowForceDeclineModal(true)} disabled={actionLoading} className="gap-1.5">
                <ThumbsDown className="h-3.5 w-3.5" />
                Force Decline / Close
              </Button>
            )}
            {availableActions.reopen && (
              <Button variant="ghost" size="sm" onClick={() => setShowReopenModal(true)} disabled={actionLoading} className="gap-1.5">
                <RotateCcw className="h-3.5 w-3.5" />
                Reopen Case
              </Button>
            )}
          </div>

          {/* Validation result */}
          {validationResult && Object.keys(validationResult).length > 0 && (
            <div className={`rounded-md border px-3 py-2 text-sm ${validationResult.executable ? "border-emerald-200 bg-emerald-50 dark:border-emerald-800 dark:bg-emerald-950/10" : "border-destructive/30 bg-destructive/10 text-destructive"}`}>
              <div className="font-medium">
                {validationResult.executable ? "Validation Passed" : "Validation Failed"}
                {validationResult.risk_level && (
                  <Badge variant={validationResult.risk_level === "critical" ? "destructive" : validationResult.risk_level === "high" ? "default" : "secondary"} className="ml-2 text-xs">
                    {validationResult.risk_level} risk
                  </Badge>
                )}
              </div>
              {validationResult.reasons && validationResult.reasons.length > 0 && (
                <ul className="mt-1 list-disc list-inside text-xs">
                  {validationResult.reasons.map((r: string, i: number) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              )}
              {validationResult.blocked_tasks && validationResult.blocked_tasks.length > 0 && (
                <div className="mt-1 text-xs">Blocked tasks: {validationResult.blocked_tasks.join(", ")}</div>
              )}
            </div>
          )}

          {/* Manual override metadata preview */}
          {manualOverride.admin_reason && (
            <div className="rounded-md border border-muted bg-muted/30 px-3 py-2 text-xs space-y-1">
              <div><span className="font-medium">Admin reason:</span> {manualOverride.admin_reason}</div>
              {manualOverride.business_justification && (
                <div><span className="font-medium">Business justification:</span> {manualOverride.business_justification}</div>
              )}
              {manualOverride.expected_impact && (
                <div><span className="font-medium">Expected impact:</span> {manualOverride.expected_impact}</div>
              )}
              {manualOverride.rollback_plan_yaml && (
                <div><span className="font-medium">Rollback plan:</span> Present</div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Modals */}
      {showEditor && (
        <ManualRemediationEditor
          investigation={investigation}
          onClose={() => setShowEditor(false)}
          onMutate={onMutate}
        />
      )}

      {showApproveModal && (
        <ManualRemediationApproveModal
          investigation={investigation}
          onClose={() => setShowApproveModal(false)}
          onMutate={onMutate}
        />
      )}

      {/* Force Decline Modal */}
      {showForceDeclineModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="w-full max-w-md rounded-lg border bg-card p-6 shadow-lg">
            <h3 className="text-lg font-semibold flex items-center gap-2">
              <AlertOctagon className="h-5 w-5 text-destructive" />
              Force Decline / Close
            </h3>
            <p className="mt-2 text-sm text-muted-foreground">
              This will close the investigation without remediation. Provide a reason.
            </p>
            <textarea
              className="mt-3 w-full rounded-md border bg-background px-3 py-2 text-sm min-h-[80px]"
              placeholder="Reason (min 10 characters)..."
              value={forceDeclineReason}
              onChange={(e) => setForceDeclineReason(e.target.value)}
            />
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="outline" size="sm" onClick={() => setShowForceDeclineModal(false)}>Cancel</Button>
              <Button variant="destructive" size="sm" onClick={handleForceDecline} disabled={actionLoading || forceDeclineReason.length < 10}>
                Force Decline
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Reopen Modal */}
      {showReopenModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="w-full max-w-md rounded-lg border bg-card p-6 shadow-lg">
            <h3 className="text-lg font-semibold flex items-center gap-2">
              <RotateCcw className="h-5 w-5 text-amber-500" />
              Reopen Case
            </h3>
            <p className="mt-2 text-sm text-muted-foreground">
              This will reopen the investigation and clear any manual override state.
            </p>
            <textarea
              className="mt-3 w-full rounded-md border bg-background px-3 py-2 text-sm min-h-[80px]"
              placeholder="Reason (min 10 characters)..."
              value={reopenReason}
              onChange={(e) => setReopenReason(e.target.value)}
            />
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="outline" size="sm" onClick={() => setShowReopenModal(false)}>Cancel</Button>
              <Button variant="default" size="sm" onClick={handleReopen} disabled={actionLoading || reopenReason.length < 10}>
                Reopen
              </Button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
