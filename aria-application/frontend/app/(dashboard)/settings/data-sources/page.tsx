"use client";

import { useState, useMemo, useEffect } from "react";
import {
  Database,
  TestTube,
  Save,
  Loader2,
} from "lucide-react";
import { settingsAPI } from "@/lib/api";
import { useSettings } from "../_components/use-settings";
import { AdminSecretModal } from "../_components/admin-secret-modal";
import { PreviewModal } from "../_components/preview-modal";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { useSelectedAsset } from "@/lib/asset-context";
import { useAuth } from "@/lib/auth-context";
import { SelectedAssetBanner, GlobalScopeBanner } from "@/components/selected-asset-banner";
import type { SettingsPreviewItem } from "@/lib/api";

export default function DataSourcesSettingsPage() {
  const { getSectionMap, isLoading, mutate } = useSettings();
  const saved = getSectionMap("data_sources");
  const { toast } = useToast();

  const [form, setForm] = useState<Record<string, any>>({});
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [adminOpen, setAdminOpen] = useState(false);
  const [previewItems, setPreviewItems] = useState<SettingsPreviewItem[]>([]);

  const { selectedAssetId, setSelectedAssetId, assets } = useSelectedAsset();
  const { user } = useAuth();

  // Auto-select locked asset for server_user accounts
  useEffect(() => {
    if (user?.role === "server_user" && user?.asset_id && !selectedAssetId) {
      setSelectedAssetId(user.asset_id);
    }
  }, [user, selectedAssetId, setSelectedAssetId]);

  const selectedAsset = assets.find((a) => a.asset_id === selectedAssetId);

  const values = useMemo(() => {
    const assetSources = selectedAsset?.source_config_json || {};
    const savedPassword =
      typeof saved.elasticsearch_password === "object" && saved.elasticsearch_password !== null
        ? ""
        : (saved.elasticsearch_password || "");
    return {
      elasticsearch_url: form.elasticsearch_url ?? saved.elasticsearch_url ?? "",
      elasticsearch_user: form.elasticsearch_user ?? saved.elasticsearch_user ?? "",
      elasticsearch_password: form.elasticsearch_password ?? savedPassword,
      wazuh_index_pattern: form.wazuh_index_pattern ?? assetSources.wazuh?.index_pattern ?? saved.wazuh_index_pattern ?? "",
      falco_index_pattern: form.falco_index_pattern ?? assetSources.falco?.index_pattern ?? saved.falco_index_pattern ?? "",
      suricata_index_pattern: form.suricata_index_pattern ?? assetSources.suricata?.index_pattern ?? saved.suricata_index_pattern ?? "",
      filebeat_index_pattern: form.filebeat_index_pattern ?? assetSources.filebeat?.index_pattern ?? saved.filebeat_index_pattern ?? "",
      telegraf_index_pattern: form.telegraf_index_pattern ?? assetSources.telegraf?.index_pattern ?? saved.telegraf_index_pattern ?? "",
      elasticsearch_use_ssl: form.elasticsearch_use_ssl ?? saved.elasticsearch_use_ssl ?? false,
    };
  }, [form, saved, selectedAsset]);

  const changed = useMemo(() => {
    return Object.keys(form).length > 0;
  }, [form]);

  const update = (key: string, val: any) => setForm((prev) => ({ ...prev, [key]: val }));

  const handleTest = async (useSaved: boolean) => {
    setTesting(true);
    try {
      const body: Record<string, any> | undefined = useSaved ? undefined : { ...values };
      if (body && !Object.prototype.hasOwnProperty.call(form, "elasticsearch_password")) {
        delete body.elasticsearch_password;
      }
      const res = await settingsAPI.testElasticsearch(body);
      toast({
        title: res.status === "success" ? "Connection OK" : res.status === "warning" ? "Connection Warning" : "Connection Failed",
        description: res.message,
        variant: res.status === "failed" ? "destructive" : "default",
      });
    } catch (err: any) {
      toast({ title: "Test Failed", description: err.message, variant: "destructive" });
    } finally {
      setTesting(false);
    }
  };

  const handleSavePreview = async () => {
    const changes: Record<string, any> = {};
    Object.keys(form).forEach((k) => {
      (changes as any)[k] = (values as any)[k];
    });
    if (Object.keys(changes).length === 0) {
      toast({ title: "No changes", description: "Nothing to save." });
      return;
    }
    try {
      const preview = await settingsAPI.preview({ changes });
      setPreviewItems(preview.preview);
      setPreviewOpen(true);
    } catch (err: any) {
      toast({ title: "Preview Failed", description: err.message, variant: "destructive" });
    }
  };

  const handleConfirmSave = async (secret: string) => {
    const changes: Record<string, any> = {};
    Object.keys(form).forEach((k) => {
      (changes as any)[k] = (values as any)[k];
    });
    setSaving(true);
    try {
      const result = await settingsAPI.update({ changes, reload: true }, secret);
      toast({ title: "Settings Saved", description: `Applied: ${result.applied.join(", ") || "none"}` });
      if (result.requires_restart?.length) {
        toast({ title: "Restart Required", description: `Changes require restart: ${result.requires_restart.join(", ")}` });
      }
      setForm({});
      await mutate();
      try {
        await settingsAPI.reload(secret);
      } catch {
        // ignore
      }
    } catch (err: any) {
      toast({ title: "Save Failed", description: err.message, variant: "destructive" });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex flex-col">
      <PageHeader title="Data Sources" description="Elasticsearch and index configuration" />
      <div className="flex-1 space-y-6 p-6">
        <SelectedAssetBanner />
        <GlobalScopeBanner />

        <Card>
          <CardHeader>
            <CardTitle className="text-base font-medium flex items-center gap-2">
              <Database className="h-5 w-5 text-primary" />
              Elasticsearch
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="es-url">Elasticsearch URL</Label>
                <Input id="es-url" value={values.elasticsearch_url} onChange={(e) => update("elasticsearch_url", e.target.value)} placeholder="https://localhost:9200" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="es-user">Username</Label>
                <Input id="es-user" value={values.elasticsearch_user} onChange={(e) => update("elasticsearch_user", e.target.value)} placeholder="elastic" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="es-password">Password</Label>
                <Input
                  id="es-password"
                  type="password"
                  value={values.elasticsearch_password || ""}
                  onChange={(e) => update("elasticsearch_password", e.target.value)}
                  placeholder={saved.elasticsearch_password ? "configured" : "not configured"}
                />
                <p className="text-xs text-muted-foreground">
                  {saved.elasticsearch_password ? "Password is configured" : "No password set"}
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="es-ssl">Use SSL</Label>
                <div className="flex items-center gap-3 pt-2">
                  <Switch id="es-ssl" checked={!!values.elasticsearch_use_ssl} onCheckedChange={(v) => update("elasticsearch_use_ssl", v)} />
                  <span className="text-sm text-muted-foreground">{values.elasticsearch_use_ssl ? "Enabled" : "Disabled"}</span>
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <p className="text-sm font-medium">Source Index Patterns</p>
              <p className="text-xs text-muted-foreground">
                Each alert source maps to an Elasticsearch index pattern. If multiple sources share the same index, it is shown clearly.
              </p>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="wazuh-pattern">Wazuh Index</Label>
                <Input id="wazuh-pattern" value={values.wazuh_index_pattern} onChange={(e) => update("wazuh_index_pattern", e.target.value)} placeholder="wazuh-alerts-*" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="falco-pattern">Falco Index</Label>
                <Input id="falco-pattern" value={values.falco_index_pattern} onChange={(e) => update("falco_index_pattern", e.target.value)} placeholder="falco-*" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="filebeat-pattern">Filebeat Index</Label>
                <Input id="filebeat-pattern" value={values.filebeat_index_pattern} onChange={(e) => update("filebeat_index_pattern", e.target.value)} placeholder="filebeat-*" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="suricata-pattern">Suricata Index</Label>
                <Input id="suricata-pattern" value={values.suricata_index_pattern} onChange={(e) => update("suricata_index_pattern", e.target.value)} placeholder="suricata-* or filebeat-*" />
                {values.suricata_index_pattern === values.filebeat_index_pattern && values.suricata_index_pattern && (
                  <p className="text-xs text-amber-600">Suricata is currently collected through Filebeat.</p>
                )}
              </div>
              <div className="space-y-2 md:col-span-2">
                <Label htmlFor="telegraf-pattern">Telegraf Index</Label>
                <Input id="telegraf-pattern" value={values.telegraf_index_pattern} onChange={(e) => update("telegraf_index_pattern", e.target.value)} placeholder="telegraf-*" />
              </div>
            </div>
          </CardContent>
          <CardFooter className="flex flex-wrap gap-3 border-t pt-4">
            <Button variant="outline" onClick={() => handleTest(true)} disabled={testing || isLoading}>
              <TestTube className="mr-2 h-4 w-4" />
              {testing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              Test Saved Settings
            </Button>
            <Button variant="outline" onClick={() => handleTest(false)} disabled={testing}>
              <TestTube className="mr-2 h-4 w-4" />
              Test Current Form Values
            </Button>
            <Button onClick={handleSavePreview} disabled={saving || !changed}>
              <Save className="mr-2 h-4 w-4" />
              {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              Save
            </Button>
          </CardFooter>
        </Card>
      </div>

      <PreviewModal
        open={previewOpen}
        onOpenChange={setPreviewOpen}
        preview={previewItems}
        onConfirm={() => {
          setPreviewOpen(false);
          setAdminOpen(true);
        }}
      />
      <AdminSecretModal
        open={adminOpen}
        onOpenChange={setAdminOpen}
        onConfirm={handleConfirmSave}
        title="Confirm Save"
        description="Enter the admin secret to apply these data source changes."
      />
    </div>
  );
}
