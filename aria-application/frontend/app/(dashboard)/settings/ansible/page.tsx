"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  useSettingsSection,
  SettingsField,
  SavePreviewModal,
  TestResultBanner,
} from "@/components/settings-forms";
import { settingsAPI, assetsAPI, type AnsibleConfig } from "@/lib/api";
import useSWR from "swr";
import Link from "next/link";
import { getAdminSecret } from "@/lib/admin-secret";
import { useAuth } from "@/lib/auth-context";

function AnsibleSettingsInner() {
  const { values, mutate: mutateSettings, isLoading: settingsLoading } = useSettingsSection("ansible");
  const [form, setForm] = useState<Record<string, string>>({});
  const [testResult, setTestResult] = useState<{ status: string; message: string; output?: string; error?: string; uses_global_fallback?: boolean } | null>(null);
  const [saving, setSaving] = useState(false);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [selectedAsset, setSelectedAsset] = useState<string>("_global");
  const [assetForm, setAssetForm] = useState<Record<string, any>>({});
  // Temporary UI state for raw credential values (not persisted, sent to env-var endpoint)
  const [rawPassword, setRawPassword] = useState("");
  const [rawBecomePassword, setRawBecomePassword] = useState("");

  const { user } = useAuth();

  const { data: assetsData } = useSWR("assets-list-ansible", () => assetsAPI.list());
  const assets = assetsData?.assets?.filter((a) => a.enabled) || [];

  // Read ?asset_id= from URL on mount / when assets load
  const searchParams = useSearchParams();
  useEffect(() => {
    // Lock to user's asset for server_user accounts
    if (user?.role === "server_user" && user?.asset_id) {
      setSelectedAsset(user.asset_id);
      return;
    }
    const urlAssetId = searchParams.get("asset_id");
    if (urlAssetId && assets.some((a) => a.asset_id === urlAssetId)) {
      setSelectedAsset(urlAssetId);
    }
  }, [searchParams, assets, user]);

  // Reset test result and raw passwords when switching assets
  useEffect(() => {
    setTestResult(null);
    setRawPassword("");
    setRawBecomePassword("");
  }, [selectedAsset]);

  // Fetch per-asset ansible config when an asset is selected
  const { data: assetAnsible, mutate: mutateAssetAnsible } = useSWR(
    selectedAsset !== "_global" ? ["asset-ansible", selectedAsset] : null,
    () => assetsAPI.getAnsible(selectedAsset)
  );

  // Sync assetForm when asset ansible data loads
  useEffect(() => {
    if (assetAnsible?.ansible) {
      const a = assetAnsible.ansible;
      setAssetForm({
        ansible_host: a.ansible_host || "",
        ansible_user: a.ansible_user || "",
        ansible_port: String(a.ansible_port || 22),
        auth_type: a.auth_type || "private_key",
        ssh_key_ref: a.ssh_key_ref || "",
        password_secret_ref: a.password_secret_ref || "",
        become_method: a.become_method || "sudo",
        become_password_secret_ref: a.become_password_secret_ref || "",
        remediation_enabled: a.remediation_enabled ?? false,
      });
    } else {
      setAssetForm({});
    }
  }, [assetAnsible]);

  // ── Global mode helpers ───────────────────────────────────────────────────
  const getField = (key: string) => {
    if (form[key] !== undefined) return form[key];
    const v = values.find((x: any) => x.key === key);
    if (!v) return "";
    if (v.secret) return v.value?.configured ? "__configured__" : "";
    return String(v.value ?? "");
  };

  const setField = (key: string, val: string) => setForm((prev) => ({ ...prev, [key]: val }));

  const savedConnMode = String(values.find((x: any) => x.key === "ansible_connection_auth_mode")?.value || "ssh_key");
  const savedBecomeMode = String(values.find((x: any) => x.key === "ansible_become_mode")?.value || "none");
  const connMode = form.ansible_connection_auth_mode ?? savedConnMode;
  const becomeMode = form.ansible_become_mode ?? savedBecomeMode;
  const isLocal = connMode === "local";

  // ── Global mode build/save/test ───────────────────────────────────────────
  const buildGlobalChanges = () => {
    const changes: Record<string, any> = {};
    if (form.ansible_enabled !== undefined) changes.ansible_enabled = form.ansible_enabled === "true";
    if (!isLocal) {
      if (form.ansible_remote_host !== undefined) changes.ansible_remote_host = form.ansible_remote_host;
      if (form.ansible_remote_user !== undefined) changes.ansible_remote_user = form.ansible_remote_user;
      if (form.ansible_ssh_port !== undefined) changes.ansible_ssh_port = parseInt(form.ansible_ssh_port, 10);
    } else {
      changes.ansible_remote_host = "localhost";
    }
    if (connMode === "ssh_key") {
      if (form.ansible_ssh_key !== undefined) changes.ansible_ssh_key = form.ansible_ssh_key;
      if (form.ansible_connection_auth_mode !== undefined) changes.ansible_ssh_password = "";
    } else if (connMode === "ssh_password") {
      if (form.ansible_ssh_password !== undefined && form.ansible_ssh_password !== "__configured__") {
        changes.ansible_ssh_password = form.ansible_ssh_password;
      }
      if (form.ansible_connection_auth_mode !== undefined) changes.ansible_ssh_key = "";
    } else if (connMode === "local") {
      changes.ansible_ssh_key = "";
      changes.ansible_ssh_password = "";
    }
    if (form.ansible_timeout !== undefined) changes.ansible_timeout = parseInt(form.ansible_timeout, 10);
    if (becomeMode === "none") {
      changes.ansible_become_method = "none";
      changes.ansible_become_password = "";
    } else if (becomeMode === "passwordless") {
      changes.ansible_become_method = "sudo";
      changes.ansible_become_password = "";
    } else if (becomeMode === "sudo_password") {
      changes.ansible_become_method = "sudo";
      if (form.ansible_become_password !== undefined && form.ansible_become_password !== "__configured__") {
        changes.ansible_become_password = form.ansible_become_password;
      }
    }
    return changes;
  };

  const handleGlobalTest = async (useSaved: boolean) => {
    setTestResult(null);
    try {
      const payload = useSaved
        ? undefined
        : {
            ansible_remote_host: getField("ansible_remote_host"),
            ansible_remote_user: getField("ansible_remote_user"),
            ansible_ssh_key: connMode === "ssh_key" ? getField("ansible_ssh_key") : undefined,
            ansible_ssh_password: connMode === "ssh_password" ? (getField("ansible_ssh_password") === "__configured__" ? undefined : getField("ansible_ssh_password")) : undefined,
            ansible_become_password: becomeMode === "sudo_password" ? (getField("ansible_become_password") === "__configured__" ? undefined : getField("ansible_become_password")) : undefined,
          };
      const res = await settingsAPI.testAnsiblePreflight(payload);
      setTestResult({ status: res.status, message: res.message });
    } catch (e: any) {
      setTestResult({ status: "failed", message: e.message || "Test failed" });
    }
  };

  const handleGlobalSave = async () => {
    const changes = buildGlobalChanges();
    if (Object.keys(changes).length === 0) return;
    setSaving(true);
    try {
      const secret = getAdminSecret();
      const res = await settingsAPI.update({ changes, reload: true }, secret || undefined);
      if (res.errors.length) {
        setTestResult({ status: "failed", message: res.errors.join("; ") });
      } else {
        setTestResult({ status: "success", message: "Saved successfully." + (res.requires_restart.length ? " Restart required for: " + res.requires_restart.join(", ") : "") });
        setForm({});
        mutateSettings();
      }
    } catch (e: any) {
      setTestResult({ status: "failed", message: e.message || "Save failed" });
    } finally {
      setSaving(false);
      setPreviewOpen(false);
    }
  };

  // ── Per-asset mode save/test ──────────────────────────────────────────────
  const handleAssetTest = async (useSaved: boolean) => {
    setTestResult(null);
    try {
      const secret = getAdminSecret();
      let body: AnsibleConfig | undefined = undefined;
      const testSecret = secret || undefined;

      if (!useSaved) {
        // If raw passwords are entered, write them to .env first so the test can use them
        const passwordEnvKey = `ARIA_ASSET_${selectedAsset.toUpperCase()}_ANSIBLE_PASSWORD`;
        const becomeEnvKey = `ARIA_ASSET_${selectedAsset.toUpperCase()}_BECOME_PASSWORD`;
        if (assetForm.auth_type === "password" && rawPassword.trim() && testSecret) {
          await settingsAPI.setEnvVar(passwordEnvKey, rawPassword.trim(), testSecret);
        }
        if (assetForm.become_method !== "none" && rawBecomePassword.trim() && testSecret) {
          await settingsAPI.setEnvVar(becomeEnvKey, rawBecomePassword.trim(), testSecret);
        }

        // Test current form values
        body = {
          ansible_host: assetForm.ansible_host || undefined,
          ansible_user: assetForm.ansible_user || undefined,
          ansible_port: assetForm.ansible_port ? parseInt(assetForm.ansible_port, 10) : undefined,
          auth_type: assetForm.auth_type || "private_key",
          ssh_key_ref: assetForm.ssh_key_ref || undefined,
          password_secret_ref: assetForm.auth_type === "password" ? (rawPassword.trim() ? passwordEnvKey : (assetForm.password_secret_ref || undefined)) : undefined,
          become_method: assetForm.become_method || "sudo",
          become_password_secret_ref: assetForm.become_method !== "none" ? (rawBecomePassword.trim() ? becomeEnvKey : (assetForm.become_password_secret_ref || undefined)) : undefined,
          remediation_enabled: Boolean(assetForm.remediation_enabled),
        };
      }
      const res = await assetsAPI.testConnection(selectedAsset, testSecret, body);
      let message = res.message;
      if (res.uses_global_fallback) {
        message += " (Using global legacy credentials as fallback.)";
      }
      setTestResult({ status: res.status, message, output: res.output, error: res.error, uses_global_fallback: res.uses_global_fallback });
    } catch (e: any) {
      setTestResult({ status: "failed", message: e.message || "Test failed" });
    }
  };

  const handleAssetSave = async () => {
    setSaving(true);
    try {
      const secret = getAdminSecret();

      // If password auth and raw password entered, write to .env first
      const passwordEnvKey = `ARIA_ASSET_${selectedAsset.toUpperCase()}_ANSIBLE_PASSWORD`;
      const becomeEnvKey = `ARIA_ASSET_${selectedAsset.toUpperCase()}_BECOME_PASSWORD`;

      if (assetForm.auth_type === "password" && rawPassword.trim()) {
        await settingsAPI.setEnvVar(passwordEnvKey, rawPassword.trim(), secret || undefined);
      }
      if (assetForm.auth_type === "password" && rawBecomePassword.trim()) {
        await settingsAPI.setEnvVar(becomeEnvKey, rawBecomePassword.trim(), secret || undefined);
      }

      const payload: any = {
        ansible_host: assetForm.ansible_host || null,
        ansible_user: assetForm.ansible_user || null,
        ansible_port: assetForm.ansible_port ? parseInt(assetForm.ansible_port, 10) : 22,
        auth_type: assetForm.auth_type || "private_key",
        ssh_key_ref: assetForm.ssh_key_ref || null,
        password_secret_ref: assetForm.auth_type === "password" ? (rawPassword.trim() ? passwordEnvKey : (assetForm.password_secret_ref || null)) : null,
        become_method: assetForm.become_method || "sudo",
        become_password_secret_ref: assetForm.become_method !== "none" && rawBecomePassword.trim() ? becomeEnvKey : (assetForm.become_password_secret_ref || null),
        remediation_enabled: Boolean(assetForm.remediation_enabled),
      };
      await assetsAPI.updateAnsible(selectedAsset, payload, secret || undefined);
      await mutateAssetAnsible();
      setRawPassword("");
      setRawBecomePassword("");
      setTestResult({ status: "success", message: "Asset Ansible config saved successfully." + (rawPassword.trim() || rawBecomePassword.trim() ? " Credentials loaded into the running backend (no restart required)." : "") });
    } catch (e: any) {
      setTestResult({ status: "failed", message: e.message || "Save failed" });
    } finally {
      setSaving(false);
    }
  };

  // ── Render helpers ────────────────────────────────────────────────────────
  const isPerAsset = selectedAsset !== "_global";
  const selectedAssetName = assets.find((a) => a.asset_id === selectedAsset)?.name || selectedAsset;
  const readiness = assetAnsible?.readiness;

  return (
    <div>
      <PageHeader title="Ansible / Remediation" description="Configure Ansible and remediation per server" />
      <div className="p-6 space-y-4 max-w-2xl">
        <div className="flex items-center gap-3">
          <Label className="text-sm whitespace-nowrap">Target Server</Label>
          <Select value={selectedAsset} onValueChange={setSelectedAsset} disabled={user?.role === "server_user"}>
            <SelectTrigger className="w-[280px]">
              <SelectValue placeholder="Global settings (all servers)" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="_global">Global settings (legacy fallback)</SelectItem>
              {assets.map((a) => (
                <SelectItem key={a.asset_id} value={a.asset_id}>
                  {a.name} ({a.asset_id})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {isPerAsset && (
            <Link href={`/settings/assets?edit=${selectedAsset}`} className="text-xs text-primary hover:underline">
              Edit in Assets →
            </Link>
          )}
        </div>

        {isPerAsset && readiness && (
          <Card className={readiness.remediation_enabled ? "border-emerald-200 bg-emerald-50/50" : "border-amber-200 bg-amber-50/50"}>
            <CardContent className="py-3 flex flex-wrap items-center gap-2">
              <Badge variant={readiness.remediation_enabled ? "default" : "outline"}>
                {readiness.remediation_enabled ? "Remediation Ready" : "Remediation Not Ready"}
              </Badge>
              {readiness.uses_global_fallback && (
                <Badge variant="secondary" className="text-xs">Using global fallback</Badge>
              )}
              {!readiness.ansible_host_configured && (
                <span className="text-xs text-amber-700">Missing: ansible host</span>
              )}
              {readiness.ansible_host_configured && !readiness.ansible_user_configured && (
                <span className="text-xs text-amber-700">Missing: ansible user</span>
              )}
              {readiness.ansible_host_configured && readiness.auth_type === "private_key" && !readiness.ssh_key_configured && (
                <span className="text-xs text-amber-700">Missing: SSH key file</span>
              )}
              {readiness.ansible_host_configured && readiness.auth_type === "password" && !readiness.password_configured && (
                <span className="text-xs text-amber-700">Missing: SSH password</span>
              )}
              {readiness.ansible_host_configured && readiness.ansible_user_configured && (
                readiness.auth_type === "private_key" && readiness.ssh_key_configured ||
                readiness.auth_type === "password" && readiness.password_configured
              ) && !readiness.remediation_enabled && (
                <span className="text-xs text-amber-700">Remediation disabled — check the box below</span>
              )}
            </CardContent>
          </Card>
        )}

        {isPerAsset ? (
          // ── Per-asset mode ────────────────────────────────────────────────
          <Card>
            <CardContent className="space-y-4 pt-6">
              <h3 className="text-sm font-medium text-muted-foreground">
                Configuration for <strong>{selectedAssetName}</strong>
              </h3>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>SSH Host / IP</Label>
                  <Input
                    value={assetForm.ansible_host || ""}
                    onChange={(e) => setAssetForm((p: any) => ({ ...p, ansible_host: e.target.value }))}
                    placeholder="e.g. 192.168.1.10"
                  />
                </div>
                <div>
                  <Label>SSH User</Label>
                  <Input
                    value={assetForm.ansible_user || ""}
                    onChange={(e) => setAssetForm((p: any) => ({ ...p, ansible_user: e.target.value }))}
                    placeholder="e.g. root"
                  />
                </div>
                <div>
                  <Label>SSH Port</Label>
                  <Input
                    value={assetForm.ansible_port || ""}
                    onChange={(e) => setAssetForm((p: any) => ({ ...p, ansible_port: e.target.value }))}
                    placeholder="22"
                    type="number"
                  />
                </div>
                <div>
                  <Label>Auth Method</Label>
                  <Select
                    value={assetForm.auth_type || "private_key"}
                    onValueChange={(v) => setAssetForm((p: any) => ({ ...p, auth_type: v }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="private_key">Private Key</SelectItem>
                      <SelectItem value="password">Password</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {assetForm.auth_type === "private_key" && (
                <div>
                  <div className="flex items-center justify-between">
                    <Label>SSH Private Key File Path (on ARIA server)</Label>
                    {readiness && (
                      <Badge variant={readiness.ssh_key_configured ? "default" : "outline"} className="text-xs">
                        {readiness.ssh_key_configured ? "Key file found" : "Key file missing"}
                      </Badge>
                    )}
                  </div>
                  <Input
                    value={assetForm.ssh_key_ref || ""}
                    onChange={(e) => setAssetForm((p: any) => ({ ...p, ssh_key_ref: e.target.value }))}
                    placeholder="/path/to/private_key.pem"
                  />
                </div>
              )}

              {assetForm.auth_type === "password" && (
                <div className="space-y-3">
                  <div>
                    <div className="flex items-center justify-between">
                      <Label>SSH Password</Label>
                      {readiness && (
                        <Badge variant={readiness.password_configured ? "default" : "outline"} className="text-xs">
                          {readiness.password_configured ? "Password configured" : "Password missing"}
                        </Badge>
                      )}
                    </div>
                    <Input
                      type="password"
                      value={rawPassword}
                      onChange={(e) => setRawPassword(e.target.value)}
                      placeholder={readiness?.password_configured ? "•••••••• (leave blank to keep)" : "Enter SSH password"}
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      The password is saved to the backend .env file securely. It is never stored in the database.
                    </p>
                  </div>
                  <details className="text-xs">
                    <summary className="cursor-pointer text-muted-foreground hover:text-foreground">Advanced / Manual .env</summary>
                    <div className="mt-1 p-2 bg-muted rounded-md space-y-1">
                      <p>Env var name: <code className="font-mono">ARIA_ASSET_{selectedAsset.toUpperCase()}_ANSIBLE_PASSWORD</code></p>
                      <p className="text-muted-foreground">If you prefer, add this key to .env manually and use Save above (no restart required).</p>
                    </div>
                  </details>
                </div>
              )}

              <div>
                <Label>Become Method</Label>
                <Select
                  value={assetForm.become_method || "sudo"}
                  onValueChange={(v) => setAssetForm((p: any) => ({ ...p, become_method: v }))}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="sudo">sudo</SelectItem>
                    <SelectItem value="su">su</SelectItem>
                    <SelectItem value="none">none</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {assetForm.become_method !== "none" && (
                <div className="space-y-3">
                  <div>
                    <div className="flex items-center justify-between">
                      <Label>Become / Sudo Password</Label>
                      {readiness && (
                        <Badge variant={readiness.become_password_configured ? "default" : "outline"} className="text-xs">
                          {readiness.become_password_configured ? "Password configured" : "Password missing"}
                        </Badge>
                      )}
                    </div>
                    <Input
                      type="password"
                      value={rawBecomePassword}
                      onChange={(e) => setRawBecomePassword(e.target.value)}
                      placeholder={readiness?.become_password_configured ? "•••••••• (leave blank to keep)" : "Enter sudo password"}
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      The password is saved to the backend .env file securely. It is never stored in the database.
                    </p>
                  </div>
                  <details className="text-xs">
                    <summary className="cursor-pointer text-muted-foreground hover:text-foreground">Advanced / Manual .env</summary>
                    <div className="mt-1 p-2 bg-muted rounded-md space-y-1">
                      <p>Env var name: <code className="font-mono">ARIA_ASSET_{selectedAsset.toUpperCase()}_BECOME_PASSWORD</code></p>
                      <p className="text-muted-foreground">If you prefer, add this key to .env manually and use Save above (no restart required).</p>
                    </div>
                  </details>
                </div>
              )}

              <div className="flex items-center gap-2 pt-2">
                <input
                  type="checkbox"
                  checked={Boolean(assetForm.remediation_enabled)}
                  onChange={(e) => setAssetForm((p: any) => ({ ...p, remediation_enabled: e.target.checked }))}
                />
                <Label>Enable Remediation</Label>
              </div>

              <div className="flex flex-wrap gap-2 pt-2">
                <Button variant="outline" onClick={() => handleAssetTest(true)} disabled={saving}>
                  Test Saved Config
                </Button>
                <Button variant="outline" onClick={() => handleAssetTest(false)} disabled={saving}>
                  Test Current Form Values
                </Button>
                <Button onClick={handleAssetSave} disabled={saving}>
                  {saving ? "Saving..." : "Save"}
                </Button>
              </div>
              <TestResultBanner result={testResult} />
              {testResult?.output && (
                <details className="text-xs mt-2">
                  <summary className="cursor-pointer text-muted-foreground hover:text-foreground">Test output</summary>
                  <pre className="mt-1 p-2 bg-muted rounded-md overflow-auto max-h-40 whitespace-pre-wrap">{testResult.output}</pre>
                </details>
              )}
              {testResult?.error && (
                <details className="text-xs mt-2">
                  <summary className="cursor-pointer text-muted-foreground hover:text-foreground">Error details</summary>
                  <pre className="mt-1 p-2 bg-muted rounded-md overflow-auto max-h-40 whitespace-pre-wrap text-red-600">{testResult.error}</pre>
                </details>
              )}
            </CardContent>
          </Card>
        ) : (
          // ── Global mode (legacy) ──────────────────────────────────────────
          settingsLoading ? (
            <div className="space-y-4 animate-fade-in">
              <div className="rounded-lg border p-4 space-y-3">
                <div className="h-4 w-32 bg-muted rounded" />
                <div className="h-3 w-full bg-muted rounded" />
                <div className="h-3 w-2/3 bg-muted rounded" />
              </div>
            </div>
          ) : (
            <Card>
              <CardContent className="space-y-4 pt-6">
                <SettingsField label="Ansible Enabled" value={getField("ansible_enabled")} onChange={(v) => setField("ansible_enabled", v)} type="bool" />
                <div className="space-y-2">
                  <Label className="text-base font-medium">A. Connection Authentication</Label>
                  <p className="text-xs text-muted-foreground">Choose exactly one authentication method for the target host.</p>
                  <select
                    className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                    value={connMode}
                    onChange={(e) => setField("ansible_connection_auth_mode", e.target.value)}
                  >
                    <option value="ssh_key">SSH Key</option>
                    <option value="ssh_password">SSH Password</option>
                    <option value="local">Local Connection</option>
                  </select>
                </div>

                {!isLocal && (
                  <>
                    <SettingsField label="Remote Host" value={getField("ansible_remote_host")} onChange={(v) => setField("ansible_remote_host", v)} />
                    <SettingsField label="Remote User" value={getField("ansible_remote_user")} onChange={(v) => setField("ansible_remote_user", v)} />
                    <SettingsField label="SSH Port" value={getField("ansible_ssh_port")} onChange={(v) => setField("ansible_ssh_port", v)} />
                  </>
                )}

                {connMode === "ssh_key" && (
                  <SettingsField label="SSH Key Path" value={getField("ansible_ssh_key")} onChange={(v) => setField("ansible_ssh_key", v)} />
                )}

                {connMode === "ssh_password" && (
                  <SettingsField label="SSH Password" value={getField("ansible_ssh_password")} onChange={(v) => setField("ansible_ssh_password", v)} secret />
                )}

                {!isLocal && (
                  <SettingsField label="Connection Timeout (seconds)" value={getField("ansible_timeout")} onChange={(v) => setField("ansible_timeout", v)} />
                )}

                <div className="space-y-2">
                  <Label className="text-base font-medium">B. Privilege Escalation (Become)</Label>
                  <select
                    className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                    value={becomeMode}
                    onChange={(e) => setField("ansible_become_mode", e.target.value)}
                  >
                    <option value="none">No Become</option>
                    <option value="passwordless">Sudo Passwordless</option>
                    <option value="sudo_password">Sudo with Password</option>
                  </select>
                </div>

                {becomeMode === "sudo_password" && (
                  <SettingsField label="Become Password" value={getField("ansible_become_password")} onChange={(v) => setField("ansible_become_password", v)} secret />
                )}

                <div className="flex flex-wrap gap-2 pt-2">
                  <Button variant="outline" onClick={() => handleGlobalTest(true)}>Test Saved Preflight</Button>
                  <Button variant="outline" onClick={() => handleGlobalTest(false)}>Test Current Form Values</Button>
                  <Button onClick={() => setPreviewOpen(true)} disabled={saving}>
                    {saving ? "Saving..." : "Save"}
                  </Button>
                </div>
                <TestResultBanner result={testResult} />
              </CardContent>
            </Card>
          )
        )}
      </div>

      <SavePreviewModal
        open={previewOpen}
        onClose={() => setPreviewOpen(false)}
        onConfirm={() => { handleGlobalSave(); }}
        preview={Object.entries(buildGlobalChanges()).map(([k, v]) => {
          const oldV = values.find((x: any) => x.key === k);
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

export default function AnsibleSettingsPage() {
  return (
    <Suspense fallback={<div className="p-6 space-y-4 animate-fade-in"><div className="rounded-lg border p-4 space-y-3"><div className="h-4 w-32 bg-muted rounded" /><div className="h-3 w-full bg-muted rounded" /></div></div>}>
      <AnsibleSettingsInner />
    </Suspense>
  );
}
