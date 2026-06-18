"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { assetsAPI, accountsAPI, type MonitoredAsset, type SourceConfig } from "@/lib/api";
import { useToast } from "@/components/ui/use-toast";
import { useAuth } from "@/lib/auth-context";
import { Server, Plus, Pencil, Trash2, CheckCircle, AlertTriangle, XCircle, Loader2, ChevronDown, ChevronRight, KeyRound, UserCheck } from "lucide-react";
import { getAdminSecret } from "@/lib/admin-secret";

const SOURCE_KEYS = ["wazuh", "falco", "telegraf", "filebeat", "suricata"] as const;

function sourceBadge(status: string) {
  if (status === "ok") return <Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20"><CheckCircle className="h-3 w-3 mr-1" />OK</Badge>;
  if (status === "missing") return <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500/20"><AlertTriangle className="h-3 w-3 mr-1" />Missing</Badge>;
  return <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/20"><XCircle className="h-3 w-3 mr-1" />Error</Badge>;
}

function AdvancedAnsibleSection({ form, setForm }: { form: Partial<MonitoredAsset>; setForm: React.Dispatch<React.SetStateAction<Partial<MonitoredAsset>>> }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border rounded-md">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 w-full px-3 py-2 text-xs font-medium text-muted-foreground hover:text-foreground"
      >
        {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        Advanced — Environment Variable References
      </button>
      {open && (
        <div className="px-3 pb-3 space-y-2">
          <p className="text-xs text-muted-foreground">
            ARIA stores only env-var names (not passwords) in the database. Set the actual values as environment variables on the ARIA server.
          </p>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <Label className="text-xs">Password Env Var</Label>
              <Input
                placeholder="ARIA_ASSET_<NAME>_ANSIBLE_PASSWORD"
                value={((form.ansible_config_json as any)?.password_secret_ref) || ""}
                onChange={(e) => setForm({ ...form, ansible_config_json: { ...(form.ansible_config_json || {}), password_secret_ref: e.target.value } })}
              />
            </div>
            <div>
              <Label className="text-xs">Become Password Env Var</Label>
              <Input
                placeholder="ARIA_ASSET_<NAME>_ANSIBLE_BECOME_PASSWORD"
                value={((form.ansible_config_json as any)?.become_password_secret_ref) || ""}
                onChange={(e) => setForm({ ...form, ansible_config_json: { ...(form.ansible_config_json || {}), become_password_secret_ref: e.target.value } })}
              />
            </div>
            <div>
              <Label className="text-xs">Become Method</Label>
              <Input
                placeholder="sudo"
                value={((form.ansible_config_json as any)?.become_method) || ""}
                onChange={(e) => setForm({ ...form, ansible_config_json: { ...(form.ansible_config_json || {}), become_method: e.target.value } })}
              />
            </div>
            <div>
              <Label className="text-xs">Environment</Label>
              <Input
                placeholder="e.g. production"
                value={form.environment || ""}
                onChange={(e) => setForm({ ...form, environment: e.target.value })}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function AssetsSettingsPage() {
  const { toast } = useToast();
  const { user } = useAuth();
  const router = useRouter();

  const isServerUser = user?.role === "server_user";
  const { data, mutate, isLoading } = useSWR<MonitoredAsset[]>(
    isServerUser ? ["assets", user?.asset_id] : "assets",
    async () => {
      const res = await assetsAPI.list(true, isServerUser ? user?.asset_id || undefined : undefined);
      return res.assets;
    }
  );
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<MonitoredAsset | null>(null);
  const [form, setForm] = useState<Partial<MonitoredAsset>>({});
  const [sourceChecks, setSourceChecks] = useState<Record<string, { status: string; message: string; count?: number; last_seen?: string }>>({});
  const [checking, setChecking] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);

  const openCreate = () => {
    setEditing(null);
    setForm({ enabled: true, source_config_json: {}, ansible_config_json: {} });
    setSourceChecks({});
    setDialogOpen(true);
  };

  const openEdit = (asset: MonitoredAsset) => {
    setEditing(asset);
    setForm({ ...asset });
    setSourceChecks({});
    setDialogOpen(true);
  };

  const handleCheckSource = async (source: string) => {
    const cfg = (form.source_config_json?.[source] || {}) as SourceConfig;
    setChecking((prev) => ({ ...prev, [source]: true }));
    try {
      const adminSecret = getAdminSecret();
      const res = await assetsAPI.checkSource(
        {
          source,
          index_pattern: cfg.index_pattern,
          host_name: cfg.host_name,
          agent_name: cfg.agent_name,
          agent_id: cfg.agent_id,
        },
        adminSecret || undefined
      );
      setSourceChecks((prev) => ({ ...prev, [source]: { status: res.status, message: res.message, count: res.count, last_seen: res.last_seen } }));
    } catch (e: any) {
      setSourceChecks((prev) => ({ ...prev, [source]: { status: "error", message: e.message || "Check failed" } }));
    } finally {
      setChecking((prev) => ({ ...prev, [source]: false }));
    }
  };

  const handleSave = async () => {
    if (!form.asset_id || !form.name) {
      toast({ title: "Validation Error", description: "Asset ID and Name are required.", variant: "destructive" });
      return;
    }
    if (form.enabled) {
      const hasConfiguredSource = SOURCE_KEYS.some((s) => {
        const cfg = (form.source_config_json as any)?.[s];
        return cfg?.index_pattern || cfg?.host_name;
      });
      if (!hasConfiguredSource) {
        toast({ title: "Validation Error", description: "At least one source must be configured before enabling.", variant: "destructive" });
        return;
      }
      // Only require source check pass for NEW assets or when transitioning disabled -> enabled
      const wasPreviouslyEnabled = editing?.enabled ?? false;
      const isEnablingTransition = !wasPreviouslyEnabled;
      if (!editing || isEnablingTransition) {
        const hasOkCheck = SOURCE_KEYS.some((s) => sourceChecks[s]?.status === "ok");
        if (!hasOkCheck) {
          toast({ title: "Validation Error", description: "At least one source must pass the Check before enabling.", variant: "destructive" });
          return;
        }
      }
    }
    setSaving(true);
    try {
      const adminSecret = getAdminSecret();
      if (editing) {
        await assetsAPI.update(form.asset_id, form, adminSecret || undefined);
      } else {
        await assetsAPI.create(form, adminSecret || undefined);
      }
      await mutate();
      setDialogOpen(false);
      toast({ title: "Saved", description: "Asset saved successfully." });
    } catch (e: any) {
      toast({ title: "Save Failed", description: e.message || "Unknown error", variant: "destructive" });
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (assetId: string) => {
    if (!confirm("Are you sure you want to delete this asset?")) return;
    try {
      const adminSecret = getAdminSecret();
      await assetsAPI.delete(assetId, adminSecret || undefined);
      await mutate();
      toast({ title: "Deleted", description: "Asset deleted." });
    } catch (e: any) {
      toast({ title: "Delete Failed", description: e.message || "Unknown error", variant: "destructive" });
    }
  };

  const setSourceField = (source: string, field: string, value: string) => {
    setForm((prev) => ({
      ...prev,
      source_config_json: {
        ...(prev.source_config_json || {}),
        [source]: { ...((prev.source_config_json as any)?.[source] || {}), [field]: value },
      },
    }));
  };

  return (
    <div>
      <PageHeader
        title="Assets"
        description="Manage monitored servers and endpoints"
        actions={!isServerUser ? <Button onClick={openCreate}><Plus className="h-4 w-4 mr-2" />Add Server</Button> : undefined}
      />
      <div className="p-6">
        <Card>
          <CardHeader>
            <CardTitle>Monitored Servers</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading && (
              <div className="space-y-3">
                {Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="flex items-center justify-between rounded-lg border p-4">
                    <div className="flex items-center gap-3">
                      <div className="h-5 w-5 rounded bg-muted" />
                      <div className="space-y-2">
                        <div className="h-4 w-32 bg-muted rounded" />
                        <div className="h-3 w-24 bg-muted rounded" />
                      </div>
                    </div>
                    <div className="h-8 w-16 bg-muted rounded" />
                  </div>
                ))}
              </div>
            )}
            {!isLoading && (!data || data.length === 0) && (
              <p className="text-muted-foreground">No assets configured. Click Add Server to create one.</p>
            )}
            {data && data.length > 0 && (
              <div className="space-y-3">
                {data.map((asset) => (
                  <div key={asset.asset_id} className="flex items-center justify-between rounded-lg border p-4">
                    <div className="flex items-center gap-3">
                      <Server className="h-5 w-5 text-muted-foreground" />
                      <div>
                        <div className="font-medium">{asset.name} <span className="text-muted-foreground text-sm">({asset.asset_id})</span></div>
                        <div className="text-sm text-muted-foreground">
                          {asset.hostname || asset.ip_address || "No host"} — {asset.enabled ? "Enabled" : "Disabled"}
                        </div>
                        <div className="mt-1 flex gap-2">
                          {SOURCE_KEYS.map((s) => {
                            const cfg = (asset.source_config_json?.[s] || {}) as SourceConfig;
                            return cfg.index_pattern || cfg.host_name ? (
                              <span key={s} className="text-xs uppercase tracking-wider text-muted-foreground border rounded px-1">{s}</span>
                            ) : null;
                          })}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {asset.has_aria_account ? (
                        <Badge variant="outline" className="bg-primary/10 text-primary border-primary/20 text-xs gap-1">
                          <UserCheck className="h-3 w-3" />
                          {asset.aria_account_username}
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-muted-foreground text-xs">No account</Badge>
                      )}
                      {sourceBadge(asset.validation_status)}
                      {user?.role === "super_admin" && (
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={`Ensure account for ${asset.name}`}
                          onClick={async () => {
                            try {
                              const res = await accountsAPI.ensureDefaultAccount(asset.asset_id);
                              toast({ title: res.created ? "Account Created" : "Account Reset", description: res.message });
                              mutate();
                            } catch (e: any) {
                              toast({ title: "Failed", description: e.message || "Could not ensure account", variant: "destructive" });
                            }
                          }}
                        >
                          <KeyRound className="h-4 w-4" />
                        </Button>
                      )}
                      {!isServerUser && (
                        <>
                          <Button variant="ghost" size="icon" aria-label={`Edit ${asset.name}`} onClick={() => openEdit(asset)}><Pencil className="h-4 w-4" /></Button>
                          <Button variant="ghost" size="icon" aria-label={`Delete ${asset.name}`} onClick={() => handleDelete(asset.asset_id)}><Trash2 className="h-4 w-4" /></Button>
                        </>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editing ? "Edit Server" : "Add Server"}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>Asset ID / Slug</Label>
                <Input value={form.asset_id || ""} onChange={(e) => setForm({ ...form, asset_id: e.target.value })} disabled={!!editing} />
              </div>
              <div>
                <Label>Name</Label>
                <Input value={form.name || ""} onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </div>
              <div>
                <Label>Hostname</Label>
                <Input value={form.hostname || ""} onChange={(e) => setForm({ ...form, hostname: e.target.value })} />
              </div>
              <div>
                <Label>IP Address</Label>
                <Input value={form.ip_address || ""} onChange={(e) => setForm({ ...form, ip_address: e.target.value })} />
              </div>
              <div className="flex items-center gap-2">
                <input type="checkbox" checked={form.enabled ?? true} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
                <Label>Enabled</Label>
              </div>
            </div>

            <div>
              <Label>Description</Label>
              <Input value={form.description || ""} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </div>

            <div className="space-y-3">
              <h4 className="font-medium">Source Configuration</h4>
              {SOURCE_KEYS.map((source) => (
                <Card key={source}>
                  <CardContent className="p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-medium capitalize">{source}</span>
                      <div className="flex items-center gap-2">
                        {sourceChecks[source] && sourceBadge(sourceChecks[source].status)}
                        <Button size="sm" variant="outline" onClick={() => handleCheckSource(source)} disabled={checking[source]}>
                          {checking[source] ? <Loader2 className="h-3 w-3 animate-spin" /> : "Check"}
                        </Button>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <Input placeholder="Index pattern" value={((form.source_config_json as any)?.[source]?.index_pattern) || ""} onChange={(e) => setSourceField(source, "index_pattern", e.target.value)} />
                      <Input placeholder="Host name" value={((form.source_config_json as any)?.[source]?.host_name) || ""} onChange={(e) => setSourceField(source, "host_name", e.target.value)} />
                      {source === "wazuh" && (
                        <>
                          <Input placeholder="Agent name" value={((form.source_config_json as any)?.[source]?.agent_name) || ""} onChange={(e) => setSourceField(source, "agent_name", e.target.value)} />
                          <Input placeholder="Agent ID" value={((form.source_config_json as any)?.[source]?.agent_id) || ""} onChange={(e) => setSourceField(source, "agent_id", e.target.value)} />
                        </>
                      )}
                    </div>
                    {sourceChecks[source] && (
                      <div className="text-xs text-muted-foreground space-y-1">
                        <p>{sourceChecks[source].message}</p>
                        {typeof sourceChecks[source].count === "number" && (
                          <p>Count: {sourceChecks[source].count?.toLocaleString()}</p>
                        )}
                        {sourceChecks[source].last_seen && (
                          <p>Last seen: {new Date(sourceChecks[source].last_seen).toLocaleString()}</p>
                        )}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>

            <div className="space-y-2">
              <h4 className="font-medium">Ansible / Remediation</h4>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <Label className="text-xs">SSH Host / IP</Label>
                  <Input placeholder="e.g. 192.168.1.10" value={((form.ansible_config_json as any)?.ansible_host) || ""} onChange={(e) => setForm({ ...form, ansible_config_json: { ...(form.ansible_config_json || {}), ansible_host: e.target.value } })} />
                </div>
                <div>
                  <Label className="text-xs">SSH User</Label>
                  <Input placeholder="e.g. root" value={((form.ansible_config_json as any)?.ansible_user) || ""} onChange={(e) => setForm({ ...form, ansible_config_json: { ...(form.ansible_config_json || {}), ansible_user: e.target.value } })} />
                </div>
                <div>
                  <Label className="text-xs">SSH Port</Label>
                  <Input placeholder="22" type="number" value={((form.ansible_config_json as any)?.ansible_port) || ""} onChange={(e) => setForm({ ...form, ansible_config_json: { ...(form.ansible_config_json || {}), ansible_port: parseInt(e.target.value) || 22 } })} />
                </div>
                <div>
                  <Label className="text-xs">Auth Method</Label>
                  <select
                    className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                    value={((form.ansible_config_json as any)?.auth_type) || "private_key"}
                    onChange={(e) => setForm({ ...form, ansible_config_json: { ...(form.ansible_config_json || {}), auth_type: e.target.value as any } })}
                  >
                    <option value="private_key">Private Key</option>
                    <option value="password">Password</option>
                    <option value="local">Local</option>
                  </select>
                </div>
              </div>

              {((form.ansible_config_json as any)?.auth_type) !== "password" && (
                <div>
                  <Label className="text-xs">SSH Key Path</Label>
                  <Input placeholder="/path/to/key.pem" value={((form.ansible_config_json as any)?.ssh_key_ref) || ""} onChange={(e) => setForm({ ...form, ansible_config_json: { ...(form.ansible_config_json || {}), ssh_key_ref: e.target.value } })} />
                </div>
              )}

              {((form.ansible_config_json as any)?.auth_type) === "password" && (
                <div className="flex items-center gap-2 rounded-md border bg-muted/30 px-3 py-2">
                  <span className="text-xs text-muted-foreground">Password auth requires an env-var reference.</span>
                  <Badge variant="outline" className="text-xs">
                    {(form.ansible_config_json as any)?.password_secret_ref ? "Configured" : "Not configured"}
                  </Badge>
                </div>
              )}

              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={form.remediation_enabled ?? false}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      remediation_enabled: e.target.checked,
                      ansible_config_json: {
                        ...(form.ansible_config_json || {}),
                        remediation_enabled: e.target.checked,
                      },
                    })
                  }
                />
                <Label>Enable Remediation</Label>
                <span className="text-xs text-muted-foreground ml-1">(requires SSH host)</span>
              </div>

              {/* Advanced section */}
              <AdvancedAnsibleSection form={form} setForm={setForm} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving}>{saving ? "Saving..." : "Save"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
