"use client";

import { AlertTriangle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

interface AssetReadiness {
  remediation_enabled: boolean;
  ansible_host_configured: boolean;
  ansible_user_configured: boolean;
  auth_type?: string;
  ssh_key_configured?: boolean;
  password_configured?: boolean;
}

interface AssetReadinessBannerProps {
  assetId: string;
  readiness: AssetReadiness;
}

export function AssetReadinessBanner({ assetId, readiness }: AssetReadinessBannerProps) {
  if (readiness.remediation_enabled) return null;

  const issues: string[] = [];
  if (!readiness.ansible_host_configured) {
    issues.push("missing ansible host");
  } else if (!readiness.ansible_user_configured) {
    issues.push("missing ansible user");
  } else if (readiness.auth_type === "private_key" && !readiness.ssh_key_configured) {
    issues.push("missing SSH key");
  } else if (readiness.auth_type === "password" && !readiness.password_configured) {
    issues.push("missing SSH password");
  } else {
    issues.push("remediation disabled");
  }

  return (
    <Card className="mt-2 border-amber-200 bg-amber-50/50 dark:border-amber-900/30 dark:bg-amber-900/10">
      <CardContent className="py-2 flex flex-wrap items-center gap-2 text-xs text-amber-700 dark:text-amber-400">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        <span>Remediation not ready —</span>
        {issues.map((issue, i) => (
          <span key={i}>{issue}</span>
        ))}
        <a
          href={`/settings/ansible?asset_id=${assetId}`}
          className="underline hover:text-amber-900 dark:hover:text-amber-300"
        >
          Configure in Settings →
        </a>
      </CardContent>
    </Card>
  );
}
