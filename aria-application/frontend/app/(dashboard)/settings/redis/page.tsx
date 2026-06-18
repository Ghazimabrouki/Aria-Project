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

export default function RedisSettingsPage() {
  const { values, mutate, isLoading } = useSettingsSection("redis");
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
    ["redis_host", "redis_port", "redis_db", "redis_password"].forEach((k) => {
      if (form[k] !== undefined) {
        if (k === "redis_port" || k === "redis_db") {
          changes[k] = parseInt(form[k], 10);
        } else if (k === "redis_password") {
          if (form[k] && form[k] !== "__configured__") changes[k] = form[k];
        } else {
          changes[k] = form[k];
        }
      }
    });
    return changes;
  };

  const handleTest = async (useSaved: boolean) => {
    setTestResult(null);
    try {
      const payload = useSaved
        ? undefined
        : {
            redis_host: getField("redis_host"),
            redis_port: parseInt(getField("redis_port"), 10),
            redis_db: parseInt(getField("redis_db"), 10),
            redis_password: getField("redis_password") === "__configured__" ? undefined : getField("redis_password"),
          };
      const res = await settingsAPI.testRedis(payload);
      setTestResult({ status: res.status, message: res.message });
    } catch (e: any) {
      setTestResult({ status: "failed", message: e.message || "Test failed" });
    }
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
      <PageHeader title="Redis / Deduplication" description="Redis connection and deduplication settings" />
      <div className="p-6 space-y-4 max-w-2xl">
        {isLoading ? (
          <div className="space-y-4 animate-fade-in"><div className="rounded-lg border p-4 space-y-3"><div className="h-4 w-32 bg-muted rounded" /><div className="h-3 w-full bg-muted rounded" /><div className="h-3 w-2/3 bg-muted rounded" /></div></div>
        ) : (
          <Card>
            <CardContent className="space-y-4 pt-6">
              <SettingsField label="Redis Host" value={getField("redis_host")} onChange={(v) => setField("redis_host", v)} />
              <SettingsField label="Redis Port" value={getField("redis_port")} onChange={(v) => setField("redis_port", v)} />
              <SettingsField label="Redis DB" value={getField("redis_db")} onChange={(v) => setField("redis_db", v)} />
              <SettingsField label="Redis Password" value={getField("redis_password")} onChange={(v) => setField("redis_password", v)} secret />

              <div className="flex flex-wrap gap-2 pt-2">
                <Button variant="outline" onClick={() => handleTest(true)}>Test Saved Settings</Button>
                <Button variant="outline" onClick={() => handleTest(false)}>Test Current Form Values</Button>
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
