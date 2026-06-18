"use client";

import { useState, useEffect } from "react";
import useSWR from "swr";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { settingsAPI, type SettingsResponse, type SettingsValue } from "@/lib/api";

export function useSettingsSection(sectionName: string) {
  const { data, mutate, isLoading } = useSWR<SettingsResponse>("settings", () => settingsAPI.get());
  const section = data?.sections.find((s) => s.section === sectionName);
  const values = section?.values ?? [];
  return { values, mutate, isLoading };
}

export function getValue(values: SettingsValue[], key: string): any {
  return values.find((v) => v.key === key)?.value;
}

export function getSecretStatus(values: SettingsValue[], key: string): boolean {
  const v = values.find((x) => x.key === key);
  if (!v) return false;
  if (typeof v.value === "object" && v.value !== null) {
    return v.value.configured === true;
  }
  return !!v.value;
}

export function SettingsField({
  label,
  value,
  onChange,
  type = "string",
  secret = false,
  placeholder,
  description,
}: {
  label: string;
  value: string;
  onChange: (val: string) => void;
  type?: string;
  secret?: boolean;
  placeholder?: string;
  description?: string;
}) {
  if (secret) {
    const configured = value === "__configured__";
    return (
      <div className="space-y-1.5">
        <Label>{label}</Label>
        <div className="flex items-center gap-2">
          <Badge variant={configured ? "default" : "secondary"}>
            {configured ? "Configured" : "Not configured"}
          </Badge>
          <Input
            type="password"
            placeholder={placeholder || "Replace secret..."}
            value={value === "__configured__" ? "" : value}
            onChange={(e) => onChange(e.target.value)}
            className="flex-1"
          />
        </div>
      </div>
    );
  }
  if (type === "bool") {
    return (
      <div className="flex items-center justify-between rounded-lg border p-3">
        <div className="space-y-0.5">
          <Label className="cursor-pointer">{label}</Label>
          {description && <p className="text-xs text-muted-foreground">{description}</p>}
        </div>
        <Switch checked={value === "true"} onCheckedChange={(c) => onChange(c ? "true" : "false")} />
      </div>
    );
  }
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      <Input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
    </div>
  );
}

export function SavePreviewModal({
  open,
  onClose,
  onConfirm,
  preview,
  title,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: (secret: string) => void;
  preview: { key: string; old: any; new: any; type: string }[];
  title?: string;
}) {
  const [secret, setSecret] = useState("");
  useEffect(() => {
    if (!open) setSecret("");
  }, [open]);

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{title || "Preview Changes"}</DialogTitle>
          <DialogDescription>Review changes before saving. Secrets are masked.</DialogDescription>
        </DialogHeader>
        <div className="space-y-2 max-h-64 overflow-auto">
          {preview.map((p) => (
            <div key={p.key} className="flex items-center justify-between text-sm border-b pb-2">
              <span className="font-medium">{p.key}</span>
              <span className="text-muted-foreground">
                {String(p.old ?? "")} → {String(p.new ?? "")}
              </span>
            </div>
          ))}
        </div>
        <div className="space-y-1.5">
          <Label>Admin Secret</Label>
          <Input type="password" placeholder="X-ARIA-Admin-Secret" value={secret} onChange={(e) => setSecret(e.target.value)} />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => onConfirm(secret)} disabled={!secret.trim()}>
            Confirm Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function TestResultBanner({ result }: { result: { status: string; message: string; uses_global_fallback?: boolean } | null }) {
  if (!result) return null;
  const isOk = result.status === "success" || result.status === "ok";
  return (
    <div
      className={`rounded-md border px-3 py-2 text-sm ${
        isOk ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-500" : "border-red-500/20 bg-red-500/10 text-red-500"
      }`}
    >
      {result.message}
    </div>
  );
}
