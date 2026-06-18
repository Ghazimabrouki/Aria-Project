"use client";

import { useState } from "react";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  useSettingsSection,
  SettingsField,
  SavePreviewModal,
  TestResultBanner,
} from "@/components/settings-forms";
import { settingsAPI } from "@/lib/api";

export default function WorkflowSettingsPage() {
  const { values, mutate, isLoading } = useSettingsSection("workflow");
  const [form, setForm] = useState<Record<string, string>>({});
  const [testResult, setTestResult] = useState<{ status: string; message: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [adminSecret, setAdminSecret] = useState("");
  const [askSecret, setAskSecret] = useState(false);

  const getField = (key: string) => {
    if (form[key] !== undefined) return form[key];
    const v = values.find((x) => x.key === key);
    if (!v) return "";
    if (v.secret) return v.value?.configured ? "__configured__" : "";
    return String(v.value ?? "");
  };

  const setField = (key: string, val: string) => setForm((prev) => ({ ...prev, [key]: val }));

  const buildChanges = () => {
    const changes: Record<string, any> = {};
    const keys = [
      "local_ingestion_enabled",
      "incident_auto_create_enabled",
      "auto_approve_enabled",
      "auto_approve_all_enabled",
      "auto_approve_method",
      "fix_verify_wait_minutes",
      "fix_verify_window_minutes",
      "stuck_investigation_hours",
      "stuck_running_minutes",
      "stuck_pending_hours",
      "running_investigation_timeout_minutes",
      "max_concurrent_investigations",
    ];
    keys.forEach((k) => {
      if (form[k] !== undefined) {
        if (k === "local_ingestion_enabled" || k === "incident_auto_create_enabled" || k === "auto_approve_enabled" || k === "auto_approve_all_enabled") {
          changes[k] = form[k] === "true";
        } else if ([
          "fix_verify_wait_minutes",
          "fix_verify_window_minutes",
          "stuck_investigation_hours",
          "stuck_running_minutes",
          "stuck_pending_hours",
          "running_investigation_timeout_minutes",
          "max_concurrent_investigations",
        ].includes(k)) {
          changes[k] = parseInt(form[k], 10);
        } else {
          changes[k] = form[k];
        }
      }
    });
    return changes;
  };

  const doSave = async (secretOverride?: string) => {
    const changes = buildChanges();
    if (Object.keys(changes).length === 0) return;
    setSaving(true);
    try {
      const res = await settingsAPI.update({ changes, reload: true }, secretOverride || adminSecret);
      if (res.errors.length) {
        setTestResult({ status: "failed", message: res.errors.join("; ") });
      } else {
        setTestResult({ status: "success", message: "Saved successfully." + (res.requires_restart.length ? " Restart required for: " + res.requires_restart.join(", ") : "") });
        setForm({});
        mutate();
      }
    } catch (e: any) {
      setTestResult({ status: "failed", message: e.message || "Save failed" });
    } finally {
      setSaving(false);
      setPreviewOpen(false);
    }
  };

  const openPreview = () => {
    const changes = buildChanges();
    if (Object.keys(changes).length === 0) {
      setTestResult({ status: "failed", message: "No changes to save." });
      return;
    }
    if (!adminSecret) {
      setAskSecret(true);
      return;
    }
    setPreviewOpen(true);
  };

  return (
    <div>
      <PageHeader title="SOC Workflow" description="Incident and investigation workflow settings" />
      <div className="p-6 space-y-4 max-w-2xl">
        {isLoading ? (
          <div className="space-y-4 animate-fade-in"><div className="rounded-lg border p-4 space-y-3"><div className="h-4 w-32 bg-muted rounded" /><div className="h-3 w-full bg-muted rounded" /><div className="h-3 w-2/3 bg-muted rounded" /></div></div>
        ) : (
          <Card>
            <CardContent className="space-y-4 pt-6">
              <SettingsField label="Local Ingestion Enabled" value={getField("local_ingestion_enabled")} onChange={(v) => setField("local_ingestion_enabled", v)} type="bool" />
              <SettingsField label="Auto Incident Creation" value={getField("incident_auto_create_enabled")} onChange={(v) => setField("incident_auto_create_enabled", v)} type="bool" />
              <SettingsField label="Auto Approve Enabled" value={getField("auto_approve_enabled")} onChange={(v) => setField("auto_approve_enabled", v)} type="bool" />
              <SettingsField label="Auto Approve All (Bypass All Checks)" description="When enabled, EVERY investigation is auto-approved immediately without guardrails or risk evaluation." value={getField("auto_approve_all_enabled")} onChange={(v) => setField("auto_approve_all_enabled", v)} type="bool" />
              <SettingsField label="Auto Approve Method" value={getField("auto_approve_method")} onChange={(v) => setField("auto_approve_method", v)} />
              <SettingsField label="Fix Verify Wait (minutes)" value={getField("fix_verify_wait_minutes")} onChange={(v) => setField("fix_verify_wait_minutes", v)} />
              <SettingsField label="Fix Verify Window (minutes)" value={getField("fix_verify_window_minutes")} onChange={(v) => setField("fix_verify_window_minutes", v)} />
              <SettingsField label="Stuck Investigation Threshold (hours)" value={getField("stuck_investigation_hours")} onChange={(v) => setField("stuck_investigation_hours", v)} />
              <SettingsField label="Stuck Running Threshold (minutes)" value={getField("stuck_running_minutes")} onChange={(v) => setField("stuck_running_minutes", v)} />
              <SettingsField label="Stuck Pending Threshold (hours)" value={getField("stuck_pending_hours")} onChange={(v) => setField("stuck_pending_hours", v)} />
              <SettingsField label="Running Timeout (minutes)" value={getField("running_investigation_timeout_minutes")} onChange={(v) => setField("running_investigation_timeout_minutes", v)} />
              <SettingsField label="Max Concurrent Investigations" value={getField("max_concurrent_investigations")} onChange={(v) => setField("max_concurrent_investigations", v)} />

              <div className="flex flex-wrap gap-2 pt-2">
                <Button onClick={openPreview} disabled={saving}>
                  {saving ? "Saving..." : "Save"}
                </Button>
              </div>
              <TestResultBanner result={testResult} />
            </CardContent>
          </Card>
        )}
      </div>

      <Dialog open={askSecret} onOpenChange={setAskSecret}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Admin Secret Required</DialogTitle>
          </DialogHeader>
          <div className="space-y-1.5">
            <label className="text-sm font-medium">X-ARIA-Admin-Secret</label>
            <input
              type="password"
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              value={adminSecret}
              onChange={(e) => setAdminSecret(e.target.value)}
              placeholder="Enter admin secret..."
            />
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setAskSecret(false)}>Cancel</Button>
            <Button onClick={() => { setAskSecret(false); setPreviewOpen(true); }} disabled={!adminSecret.trim()}>Continue</Button>
          </div>
        </DialogContent>
      </Dialog>

      <SavePreviewModal
        open={previewOpen}
        onClose={() => setPreviewOpen(false)}
        onConfirm={(s) => { setAdminSecret(s); doSave(s); }}
        preview={Object.entries(buildChanges()).map(([k, v]) => {
          const oldV = values.find((x) => x.key === k);
          return {
            key: k,
            old: oldV?.secret ? (oldV.value?.configured ? "configured" : "not configured") : String(oldV?.value ?? ""),
            new: oldV?.secret ? (v ? "replaced" : "not configured") : String(v),
            type: oldV?.type || "string",
          };
        })}
      />
    </div>
  );
}
