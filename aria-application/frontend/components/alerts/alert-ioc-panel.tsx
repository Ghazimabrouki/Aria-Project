"use client";

import { useRouter } from "next/navigation";
import { Copy, Search, AlertTriangle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import type { AlertIOCs } from "@/lib/api";

interface AlertIocPanelProps {
  iocs?: AlertIOCs;
}

export function AlertIocPanel({ iocs }: AlertIocPanelProps) {
  const router = useRouter();
  const safeIocs = iocs ?? {};

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const entries = Object.entries(safeIocs).filter(
    ([, vals]) => Array.isArray(vals) && vals.length > 0
  );

  if (entries.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center">
          <AlertTriangle className="mx-auto h-8 w-8 text-muted-foreground/50" />
          <p className="mt-2 text-sm text-muted-foreground">
            No IOCs extracted from this alert
          </p>
        </CardContent>
      </Card>
    );
  }

  const titleMap: Record<string, string> = {
    ips: "IP Addresses",
    ip: "IP Address",
    hashes: "File Hashes",
    hash: "Hash",
    md5: "MD5 Hashes",
    sha256: "SHA256 Hashes",
    domains: "Domains",
    domain: "Domain",
    fqdn: "FQDN",
    urls: "URLs",
    url: "URL",
    uri: "URI",
    container_id: "Container ID",
    process: "Process",
    filepath: "File Path",
    file_path: "File Path",
    filename: "Filename",
    username: "Username",
    user: "User",
    port: "Port",
    ports: "Ports",
    user_agent: "User Agent",
    registry: "Registry Key",
    command: "Command",
    cmdline: "Command Line",
  };

  const searchableKeys = new Set([
    "ips",
    "ip",
    "domains",
    "domain",
    "fqdn",
    "urls",
    "url",
    "uri",
    "hashes",
    "hash",
    "md5",
    "sha256",
    "container_id",
    "process",
    "filepath",
    "file_path",
    "filename",
    "username",
    "user",
  ]);

  return (
    <>
      {entries.map(([key, vals]) => {
        const title =
          titleMap[key] ||
          key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
        const isSearchable = searchableKeys.has(key);
        return (
          <Card key={key}>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{title}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {(vals as string[]).map((val, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between"
                  >
                    <code className="bg-muted px-2 py-1 rounded text-sm font-mono truncate max-w-[280px]">
                      {val}
                    </code>
                    <div className="flex items-center gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(val)}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                      {isSearchable && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() =>
                            router.push(`/search?q=${encodeURIComponent(val)}`)
                          }
                        >
                          <Search className="h-3 w-3" />
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        );
      })}
    </>
  );
}
