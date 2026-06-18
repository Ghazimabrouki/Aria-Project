"use client";

import { Globe } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface AlertWithMetadata {
  alert_id: string;
  severity: string;
  source: string;
  title: string;
  description?: string | null;
  source_ip?: string | null;
  dest_ip?: string | null;
  hostname?: string | null;
  rule_name?: string | null;
  tags?: string[];
  metadata?: Record<string, unknown>;
  created_at?: string | null;
}

interface RichAlertEvidenceProps {
  alerts: AlertWithMetadata[];
}

export function RichAlertEvidence({ alerts }: RichAlertEvidenceProps) {
  const richAlerts = alerts.filter(
    (a) => a.metadata && Object.keys(a.metadata).length > 0
  );

  if (richAlerts.length === 0) return null;

  return (
    <div className="space-y-3">
      {richAlerts.map((alert, idx) => {
        const meta = alert.metadata || {};
        const metaAny = meta as Record<string, any>;

        const mStr = (k: string): string | undefined => {
          const v = metaAny[k];
          if (v === null || v === undefined) return undefined;
          return String(v);
        };

        const sigId = mStr("signature_id") || mStr("sid");
        const ipsAction = mStr("ips_action");
        const netDir = mStr("network_direction");
        const srcPort = mStr("src_port");
        const dstPort = mStr("dst_port");
        const proto = mStr("proto");
        const flowId = mStr("flow_id");
        const commId = mStr("community_id");
        const httpMethod = mStr("http_method");
        const httpHost = mStr("http_host");
        const httpUrl = mStr("http_url");
        const payload = mStr("payload_printable");
        const hasHttp = !!(httpHost || httpUrl || httpMethod);

        return (
          <div key={idx} className="rounded-md border p-3">
            <div className="flex items-center gap-2 flex-wrap">
              <Badge variant="outline" className="text-xs">
                {alert.source}
              </Badge>
              {sigId && (
                <Badge variant="secondary" className="text-xs font-mono">
                  SID: {sigId}
                </Badge>
              )}
              {ipsAction && (
                <Badge
                  variant="outline"
                  className={
                    ipsAction === "blocked" || ipsAction === "drop"
                      ? "text-xs text-emerald-600 border-emerald-300"
                      : "text-xs"
                  }
                >
                  {ipsAction}
                </Badge>
              )}
              {netDir && (
                <Badge variant="outline" className="text-xs">
                  {netDir}
                </Badge>
              )}
            </div>
            <p className="mt-2 text-sm font-medium">{alert.title}</p>

            {/* Network metadata grid */}
            <div className="mt-2 grid gap-2 text-xs md:grid-cols-4">
              {alert.source_ip ? (
                <div>
                  <span className="text-muted-foreground">Src IP</span>
                  <p className="font-mono">{alert.source_ip}</p>
                </div>
              ) : null}
              {alert.dest_ip ? (
                <div>
                  <span className="text-muted-foreground">Dst IP</span>
                  <p className="font-mono">{alert.dest_ip}</p>
                </div>
              ) : null}
              {srcPort ? (
                <div>
                  <span className="text-muted-foreground">Src Port</span>
                  <p className="font-mono">{srcPort}</p>
                </div>
              ) : null}
              {dstPort ? (
                <div>
                  <span className="text-muted-foreground">Dst Port</span>
                  <p className="font-mono">{dstPort}</p>
                </div>
              ) : null}
              {proto ? (
                <div>
                  <span className="text-muted-foreground">Protocol</span>
                  <p className="font-mono">{proto}</p>
                </div>
              ) : null}
              {flowId ? (
                <div>
                  <span className="text-muted-foreground">Flow ID</span>
                  <p className="font-mono truncate">{flowId}</p>
                </div>
              ) : null}
              {commId ? (
                <div>
                  <span className="text-muted-foreground">Community ID</span>
                  <p className="font-mono truncate">{commId}</p>
                </div>
              ) : null}
            </div>

            {/* HTTP metadata */}
            {hasHttp ? (
              <div className="mt-2 rounded bg-muted/50 p-2">
                <p className="text-xs font-medium text-muted-foreground mb-1">
                  HTTP
                </p>
                <div className="grid gap-1 text-xs md:grid-cols-3">
                  {httpMethod ? (
                    <div>
                      <span className="text-muted-foreground">Method: </span>
                      <span className="font-mono">{httpMethod}</span>
                    </div>
                  ) : null}
                  {httpHost ? (
                    <div>
                      <span className="text-muted-foreground">Host: </span>
                      <span className="font-mono">{httpHost}</span>
                    </div>
                  ) : null}
                  {httpUrl ? (
                    <div>
                      <span className="text-muted-foreground">URL: </span>
                      <span className="font-mono truncate">{httpUrl}</span>
                    </div>
                  ) : null}
                </div>
              </div>
            ) : null}

            {/* Payload preview */}
            {payload ? (
              <div className="mt-2">
                <p className="text-xs font-medium text-muted-foreground mb-1">
                  Payload Preview
                </p>
                <code className="block rounded bg-muted p-2 text-xs font-mono break-all max-h-24 overflow-y-auto">
                  {payload.substring(0, 300)}
                  {payload.length > 300 ? "..." : ""}
                </code>
              </div>
            ) : null}

            {/* GeoIP */}
            {meta._geo && typeof meta._geo === "object" ? (
              <div className="mt-2 flex items-center gap-2 text-xs">
                <Globe className="h-3 w-3 text-muted-foreground" />
                <span className="text-muted-foreground">Geo:</span>
                <span>
                  {(meta._geo as any).country_name ||
                    (meta._geo as any).country_code ||
                    "Unknown"}
                  {(meta._geo as any).city_name
                    ? ` — ${(meta._geo as any).city_name}`
                    : ""}
                </span>
              </div>
            ) : null}

            {/* Tags */}
            {alert.tags && alert.tags.length > 0 ? (
              <div className="mt-2 flex flex-wrap gap-1">
                {alert.tags.slice(0, 10).map((tag, tidx) => (
                  <Badge key={tidx} variant="secondary" className="text-xs">
                    {tag}
                  </Badge>
                ))}
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
