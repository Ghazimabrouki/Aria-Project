"use client";

import { useState, useMemo } from "react";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
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

const PROVIDER_OPTIONS = [
  { value: "deterministic", label: "Deterministic only", description: "No LLM calls. Rule-based remediation planner." },
  { value: "ollama", label: "Ollama / local OpenAI-compatible", description: "Local or custom OpenAI-compatible endpoint." },
  { value: "nvidia", label: "NVIDIA NIM", description: "NVIDIA hosted NIM API." },
  { value: "openai_compatible", label: "OpenAI-compatible custom endpoint", description: "Custom endpoint with API key." },
];

export default function AISettingsPage() {
  const { values, mutate, isLoading } = useSettingsSection("ai");
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

  const activeProvider = useMemo(() => {
    const formProvider = form.active_ai_provider;
    if (formProvider) return formProvider;

    const savedEnabled = values.find((x) => x.key === "llm_enabled")?.value;
    if (savedEnabled === false || savedEnabled === "false") {
      return "deterministic";
    }
    const savedProvider = values.find((x) => x.key === "active_ai_provider")?.value;
    return String(savedProvider || "ollama");
  }, [values, form]);

  const mismatchWarning = useMemo(() => {
    const v = values.find((x) => x.key === "ai_provider_mismatch_warning");
    return v?.value as string | null;
  }, [values]);

  const buildChanges = () => {
    const changes: Record<string, any> = {};
    // Always include llm_enabled and llm_provider
    const enabled = activeProvider !== "deterministic";
    changes.llm_enabled = enabled;

    // Map frontend provider values to backend llm_provider
    let backendProvider = activeProvider;
    if (activeProvider === "openai_compatible") {
      backendProvider = "ollama"; // backend routes openai-compatible through ollama host
    } else if (activeProvider === "deterministic") {
      backendProvider = "auto";
    }
    changes.llm_provider = backendProvider;

    const keys = [
      "llm_model",
      "ollama_host",
      "ollama_timeout",
      "llm_fallback_to_pyrca",
      "openai_api_key",
      "nvidia_api_key",
    ];
    keys.forEach((k) => {
      if (form[k] !== undefined) {
        if (k === "ollama_timeout") {
          changes[k] = parseInt(form[k], 10);
        } else if (k.endsWith("_api_key")) {
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
            llm_enabled: activeProvider !== "deterministic",
          };
      const res = await settingsAPI.testAI(payload);
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
      <PageHeader title="AI / LLM" description="AI engine and LLM provider settings" />
      <div className="p-6 space-y-4 max-w-2xl">
        {isLoading ? (
          <div className="space-y-4 animate-fade-in">
            <div className="rounded-lg border p-4 space-y-3">
              <div className="h-4 w-32 bg-muted rounded" />
              <div className="h-3 w-full bg-muted rounded" />
              <div className="h-3 w-2/3 bg-muted rounded" />
            </div>
            <div className="rounded-lg border p-4 space-y-3">
              <div className="h-4 w-24 bg-muted rounded" />
              <div className="h-3 w-full bg-muted rounded" />
            </div>
          </div>
        ) : (
          <Card>
            <CardContent className="space-y-4 pt-6">
              {mismatchWarning && (
                <div className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-600">
                  ⚠️ {mismatchWarning}
                </div>
              )}

              <div className="space-y-2">
                <Label className="text-base font-medium">AI Provider Mode</Label>
                <p className="text-xs text-muted-foreground">Only one provider can be active at a time.</p>
                <RadioGroup
                  value={activeProvider}
                  onValueChange={(v) => setField("active_ai_provider", v)}
                  className="space-y-2"
                >
                  {PROVIDER_OPTIONS.map((opt) => (
                    <div key={opt.value} className="flex items-start space-x-3 rounded-lg border p-3">
                      <RadioGroupItem value={opt.value} id={`provider-${opt.value}`} className="mt-1" />
                      <div className="space-y-1">
                        <Label htmlFor={`provider-${opt.value}`} className="font-medium cursor-pointer">
                          {opt.label}
                        </Label>
                        <p className="text-xs text-muted-foreground">{opt.description}</p>
                      </div>
                    </div>
                  ))}
                </RadioGroup>
              </div>

              <SettingsField label="AI Enabled" value={activeProvider !== "deterministic" ? "true" : "false"} onChange={() => {}} type="bool" />

              {activeProvider !== "deterministic" && (
                <>
                  <SettingsField label="Model" value={getField("llm_model")} onChange={(v) => setField("llm_model", v)} />

                  {(activeProvider === "ollama" || activeProvider === "openai_compatible") && (
                    <>
                      <SettingsField label="Base URL" value={getField("ollama_host")} onChange={(v) => setField("ollama_host", v)} />
                      <SettingsField label="Timeout (seconds)" value={getField("ollama_timeout")} onChange={(v) => setField("ollama_timeout", v)} />
                    </>
                  )}

                  {activeProvider === "nvidia" && (
                    <>
                      <SettingsField label="Timeout (seconds)" value={getField("ollama_timeout")} onChange={(v) => setField("ollama_timeout", v)} />
                    </>
                  )}

                  {activeProvider === "nvidia" && (
                    <SettingsField label="NVIDIA API Key" value={getField("nvidia_api_key")} onChange={(v) => setField("nvidia_api_key", v)} secret />
                  )}

                  {activeProvider === "openai_compatible" && (
                    <SettingsField label="OpenAI-compatible API Key" value={getField("openai_api_key")} onChange={(v) => setField("openai_api_key", v)} secret />
                  )}
                </>
              )}

              {activeProvider === "deterministic" && (
                <div className="rounded-md border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-600">
                  Deterministic mode is active. AI will use rule-based fallback and deterministic remediation planning.
                </div>
              )}

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
