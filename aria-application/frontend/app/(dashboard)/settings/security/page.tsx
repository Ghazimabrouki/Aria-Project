"use client";

import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Globe,
  Gauge,
  KeyRound,
  Lock,
} from "lucide-react";
import { useSettings } from "../_components/use-settings";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function SecuritySettingsPage() {
  const { getSectionMap, isLoading, error } = useSettings();
  const values = getSectionMap("security");

  const isTrusted = values.internal_trusted_active === true || values.internal_trusted_active === "true";
  const hasAdminSecret = values.admin_secret_configured === true || values.admin_secret_configured === "true";
  const endpointsProtected = values.protected_endpoints_enabled === true || values.protected_endpoints_enabled === "true";
  const corsOrigins = values.cors_origins || "*";
  const rateLimitEnabled = values.rate_limit_enabled === true || values.rate_limit_enabled === "true";

  return (
    <div className="flex flex-col">
      <PageHeader title="Security Settings" description="Security configuration (read-only)" />
      <div className="flex-1 space-y-6 p-6">
        {error && (
          <div className="rounded-lg border border-destructive/50 bg-destructive/5 p-4 text-sm text-destructive">
            Failed to load settings. {error instanceof Error ? error.message : ""}
          </div>
        )}

        {isTrusted && (
          <div className="rounded-lg border border-warning/50 bg-warning/5 p-4 text-sm text-warning flex items-start gap-3">
            <ShieldAlert className="h-5 w-5 shrink-0 mt-0.5" />
            <div>
              <p className="font-medium">Trusted Internal Deployment</p>
              <p className="mt-1 opacity-90">
                This deployment is internal_trusted. It must run behind VPN/private LAN/firewall.
              </p>
            </div>
          </div>
        )}

        <div className="grid gap-4 md:grid-cols-2">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center gap-3">
                <Shield className="h-5 w-5 text-primary" />
                <CardTitle className="text-base font-medium">Internal Trusted Mode</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-5 w-14 bg-muted rounded animate-pulse" />
              ) : (
                <Badge variant={isTrusted ? "default" : "outline"}>
                  {isTrusted ? "Active" : "Inactive"}
                </Badge>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center gap-3">
                <KeyRound className="h-5 w-5 text-primary" />
                <CardTitle className="text-base font-medium">Admin Secret</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-5 w-20 bg-muted rounded animate-pulse" />
              ) : (
                <div className="flex items-center gap-2">
                  {hasAdminSecret ? (
                    <>
                      <ShieldCheck className="h-4 w-4 text-emerald-500" />
                      <span className="text-sm text-emerald-500 font-medium">Configured</span>
                    </>
                  ) : (
                    <>
                      <ShieldAlert className="h-4 w-4 text-destructive" />
                      <span className="text-sm text-destructive font-medium">Not Configured — Unsafe</span>
                    </>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center gap-3">
                <Lock className="h-5 w-5 text-primary" />
                <CardTitle className="text-base font-medium">Sensitive Endpoints</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-5 w-20 bg-muted rounded animate-pulse" />
              ) : (
                <Badge variant={endpointsProtected ? "default" : "destructive"}>
                  {endpointsProtected ? "Protected" : "Unprotected"}
                </Badge>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center gap-3">
                <Globe className="h-5 w-5 text-primary" />
                <CardTitle className="text-base font-medium">CORS Origins</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-5 w-20 bg-muted rounded animate-pulse" />
              ) : (
                <code className="rounded bg-muted px-2 py-1 text-xs font-mono">{String(corsOrigins)}</code>
              )}
            </CardContent>
          </Card>

          <Card className="md:col-span-2">
            <CardHeader className="pb-3">
              <div className="flex items-center gap-3">
                <Gauge className="h-5 w-5 text-primary" />
                <CardTitle className="text-base font-medium">Rate Limiting</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-5 w-20 bg-muted rounded animate-pulse" />
              ) : (
                <div className="space-y-2">
                  <Badge variant={rateLimitEnabled ? "default" : "outline"}>
                    {rateLimitEnabled ? "Enabled" : "Disabled"}
                  </Badge>
                  <p className="text-xs text-muted-foreground">
                    Rate limiting configuration is read-only. Modify via environment variables or backend configuration.
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
