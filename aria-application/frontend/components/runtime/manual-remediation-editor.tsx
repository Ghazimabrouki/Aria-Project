"use client";

import { useState } from "react";
import { FileCode, X, Save, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { runtimeAPI, type RuntimeInvestigation } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";

interface ManualRemediationEditorProps {
  investigation: RuntimeInvestigation;
  onClose: () => void;
  onMutate: () => void;
}

export function ManualRemediationEditor({ investigation, onClose, onMutate }: ManualRemediationEditorProps) {
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"details" | "playbook" | "rollback" | "verification">("details");

  const isExisting = investigation.status === "manual_remediation_draft" || investigation.status === "manual_remediation_validating";
  const existing = investigation.manual_override_json || {};

  const [adminReason, setAdminReason] = useState(existing.admin_reason || "");
  const [businessJustification, setBusinessJustification] = useState(existing.business_justification || "");
  const [targetScope, setTargetScope] = useState(existing.target_scope_confirmation || "");
  const [expectedImpact, setExpectedImpact] = useState(existing.expected_impact || "");
  const [rollbackPlan, setRollbackPlan] = useState(existing.rollback_plan_yaml || "");
  const [verificationPlan, setVerificationPlan] = useState(existing.verification_plan_yaml || "");
  const [playbookYaml, setPlaybookYaml] = useState(investigation.playbook_yaml || "");

  const canCreate =
    adminReason.length >= 10 &&
    businessJustification.length >= 10 &&
    targetScope.length >= 5 &&
    expectedImpact.length >= 5 &&
    rollbackPlan.length >= 50 &&
    verificationPlan.length >= 20;

  const handleCreate = async () => {
    if (!canCreate) {
      toast({ title: "Missing fields", description: "Please fill all required fields with minimum lengths.", variant: "destructive" });
      return;
    }
    setLoading(true);
    try {
      await runtimeAPI.manualRemediation.create(investigation.id, {
        admin_reason: adminReason,
        business_justification: businessJustification,
        target_scope_confirmation: targetScope,
        expected_impact: expectedImpact,
        rollback_plan_yaml: rollbackPlan,
        verification_plan_yaml: verificationPlan,
      });
      toast({ title: "Draft created", description: "Manual remediation draft created successfully." });
      onMutate();
      setActiveTab("playbook");
    } catch (err: any) {
      toast({ title: "Error", description: err?.message || "Failed to create draft.", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const handleSavePlaybook = async () => {
    if (!playbookYaml || playbookYaml.length < 50) {
      toast({ title: "Playbook too short", description: "Playbook YAML must be at least 50 characters.", variant: "destructive" });
      return;
    }
    setLoading(true);
    try {
      await runtimeAPI.manualRemediation.updatePlaybook(investigation.id, playbookYaml);
      toast({ title: "Playbook saved", description: "Manual remediation playbook updated." });
      onMutate();
    } catch (err: any) {
      toast({ title: "Error", description: err?.message || "Failed to save playbook.", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-lg border bg-card shadow-lg">
        <div className="flex items-center justify-between border-b px-4 py-3">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <FileCode className="h-5 w-5 text-amber-500" />
            {isExisting ? "Edit Manual Remediation" : "Create Manual Remediation"}
          </h3>
          <Button variant="ghost" size="icon" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </div>

        {/* Tabs */}
        <div className="flex border-b">
          {(["details", "playbook", "rollback", "verification"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 text-sm font-medium capitalize ${activeTab === tab ? "border-b-2 border-primary text-primary" : "text-muted-foreground hover:text-foreground"}`}
            >
              {tab}
            </button>
          ))}
        </div>

        <div className="p-4 space-y-4">
          {activeTab === "details" && (
            <div className="space-y-3">
              <div>
                <label className="text-sm font-medium">Admin Reason <span className="text-destructive">*</span></label>
                <textarea
                  className="mt-1 w-full rounded-md border bg-background px-3 py-2 text-sm min-h-[60px]"
                  placeholder="Why are you overriding the system planner? (min 10 chars)"
                  value={adminReason}
                  onChange={(e) => setAdminReason(e.target.value)}
                />
                {adminReason.length > 0 && adminReason.length < 10 && (
                  <p className="text-xs text-destructive mt-1">Must be at least 10 characters</p>
                )}
              </div>
              <div>
                <label className="text-sm font-medium">Business Justification <span className="text-destructive">*</span></label>
                <textarea
                  className="mt-1 w-full rounded-md border bg-background px-3 py-2 text-sm min-h-[60px]"
                  placeholder="Business justification (min 10 chars)"
                  value={businessJustification}
                  onChange={(e) => setBusinessJustification(e.target.value)}
                />
              </div>
              <div>
                <label className="text-sm font-medium">Target Scope Confirmation <span className="text-destructive">*</span></label>
                <input
                  className="mt-1 w-full rounded-md border bg-background px-3 py-2 text-sm"
                  placeholder="Confirm target scope (min 5 chars)"
                  value={targetScope}
                  onChange={(e) => setTargetScope(e.target.value)}
                />
              </div>
              <div>
                <label className="text-sm font-medium">Expected Impact <span className="text-destructive">*</span></label>
                <textarea
                  className="mt-1 w-full rounded-md border bg-background px-3 py-2 text-sm min-h-[60px]"
                  placeholder="What do you expect this remediation to do? (min 5 chars)"
                  value={expectedImpact}
                  onChange={(e) => setExpectedImpact(e.target.value)}
                />
              </div>
              {!isExisting && (
                <Button onClick={handleCreate} disabled={loading || !canCreate} className="w-full gap-1.5">
                  <CheckCircle2 className="h-4 w-4" />
                  Create Draft
                </Button>
              )}
            </div>
          )}

          {activeTab === "playbook" && (
            <div className="space-y-3">
              <div className="text-xs text-muted-foreground">
                Write or edit the Ansible playbook YAML. This playbook will be executed on the target host.
              </div>
              <textarea
                className="w-full rounded-md border bg-background px-3 py-2 text-xs font-mono min-h-[300px]"
                placeholder="---\n- name: Manual Remediation\n  hosts: localhost\n  tasks:\n    ..."
                value={playbookYaml}
                onChange={(e) => setPlaybookYaml(e.target.value)}
              />
              <Button onClick={handleSavePlaybook} disabled={loading || playbookYaml.length < 50} className="w-full gap-1.5">
                <Save className="h-4 w-4" />
                Save Playbook
              </Button>
            </div>
          )}

          {activeTab === "rollback" && (
            <div className="space-y-3">
              <div className="text-xs text-muted-foreground">
                Describe the rollback plan. How will you reverse this change if something goes wrong?
              </div>
              <textarea
                className="w-full rounded-md border bg-background px-3 py-2 text-xs font-mono min-h-[200px]"
                placeholder="Rollback plan YAML or description..."
                value={rollbackPlan}
                onChange={(e) => setRollbackPlan(e.target.value)}
              />
            </div>
          )}

          {activeTab === "verification" && (
            <div className="space-y-3">
              <div className="text-xs text-muted-foreground">
                Describe how you will verify the remediation worked.
              </div>
              <textarea
                className="w-full rounded-md border bg-background px-3 py-2 text-xs font-mono min-h-[200px]"
                placeholder="Verification plan..."
                value={verificationPlan}
                onChange={(e) => setVerificationPlan(e.target.value)}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
