"use client";

import { BookOpen, Fingerprint, Server, FileCode, Globe, Shield, CheckCircle2, AlertCircle, Clock, Copy, Search, Eye } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useRouter } from "next/navigation";

interface AttackNarrativeCardProps {
  text: string;
}

function parseSections(text: string): { title: string; lines: string[] }[] {
  const lines = text.split("\n");
  const sections: { title: string; lines: string[] }[] = [];
  let current: { title: string; lines: string[] } | null = null;

  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    const headerMatch = line.match(/^---\s*(.+?)\s*---$/);
    if (headerMatch) {
      current = { title: headerMatch[1], lines: [] };
      sections.push(current);
      continue;
    }
    if (current) current.lines.push(raw);
  }
  return sections;
}

function parseKeyValue(lines: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of lines) {
    const m = line.match(/^\s*[-*]?\s*([^:]+):\s*(.+)$/);
    if (m) out[m[1].trim()] = m[2].trim();
  }
  return out;
}

function parseNumberedSteps(lines: string[]): { num: number; text: string }[] {
  const steps: { num: number; text: string }[] = [];
  for (const line of lines) {
    const m = line.trim().match(/^(\d+)\.\s*(.+)$/);
    if (m) steps.push({ num: parseInt(m[1]), text: m[2].trim() });
  }
  return steps;
}

const STEP_ICONS: Record<string, React.ElementType> = {
  "initial access": Fingerprint,
  "reconnaissance": Search,
  "tools": FileCode,
  "actions": Shield,
  "persistence": Clock,
  "impact": AlertCircle,
  "detection": Eye,
  "target": Server,
  "evidence": CheckCircle2,
  "remediation": CheckCircle2,
  "monitoring": Clock,
  "root cause": AlertCircle,
};

function stepIcon(text: string): React.ElementType {
  const lower = text.toLowerCase();
  for (const [key, Icon] of Object.entries(STEP_ICONS)) {
    if (lower.includes(key)) return Icon;
  }
  return CheckCircle2;
}

function TimelineStep({ num, text, isLast }: { num: number; text: string; isLast: boolean }) {
  const Icon = stepIcon(text);
  return (
    <div className="flex gap-3">
      <div className="flex flex-col items-center">
        <div className="flex h-7 w-7 items-center justify-center rounded-full bg-primary/10 text-primary text-xs font-bold shrink-0">
          {num}
        </div>
        {!isLast && <div className="w-px flex-1 bg-border my-1" />}
      </div>
      <div className="pb-4 min-w-0">
        <div className="flex items-center gap-2">
          <Icon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
          <p className="text-sm leading-relaxed">{text}</p>
        </div>
      </div>
    </div>
  );
}

export function AttackNarrativeCard({ text }: AttackNarrativeCardProps) {
  const router = useRouter();
  const sections = parseSections(text);
  const copyToClipboard = (t: string) => navigator.clipboard.writeText(t);

  const attackChain = sections.find((s) => s.title.toLowerCase().includes("attack chain"));
  const threatIntel = sections.find((s) => s.title.toLowerCase().includes("threat intelligence"));
  const rootCause = sections.find((s) => s.title.toLowerCase().includes("root cause"));
  const timelineGaps = sections.find((s) => s.title.toLowerCase().includes("timeline"));
  const assetInventory = sections.find((s) => s.title.toLowerCase().includes("asset inventory"));

  // If no section delimiters found, treat the whole text as a single narrative
  const hasSections = sections.length > 0;
  const fallbackText = !hasSections ? text.trim() : "";

  const steps = attackChain ? parseNumberedSteps(attackChain.lines) : [];
  const threatKv = threatIntel ? parseKeyValue(threatIntel.lines) : {};
  const rootText = rootCause ? rootCause.lines.join(" ").trim() : "";
  const assetKv = assetInventory ? parseKeyValue(assetInventory.lines) : {};

  // Extract IPs, files, domains from threat intel values
  const allThreatValues = Object.values(threatKv).join(" ");
  const ipMatches = allThreatValues.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  const domainMatches = allThreatValues.match(/\b[A-Za-z0-9][-A-Za-z0-9]*\.[A-Za-z]{2,}\b/gi) || [];
  const fileMatches = allThreatValues.match(/\/[\w/._-]+/g) || [];
  const mitreMatches = allThreatValues.match(/T\d{4}(?:\.\d{3})?/g) || [];

  return (
    <Card className="border-border overflow-hidden">
      <CardHeader className="pb-3 bg-muted/30">
        <div className="flex items-center gap-2">
          <BookOpen className="h-5 w-5 text-primary" />
          <CardTitle className="text-base font-medium">Attack Narrative</CardTitle>
        </div>
      </CardHeader>

      <CardContent className="space-y-5 pt-4">
        {/* Plain text fallback when no section delimiters are present */}
        {fallbackText && (
          <div className="rounded-lg border bg-muted/20 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground mb-2">Narrative</p>
            <p className="text-sm leading-relaxed whitespace-pre-wrap">{fallbackText}</p>
          </div>
        )}

        {/* Attack Chain Timeline */}
        {steps.length > 0 && (
          <div>
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground mb-3">Attack Chain</p>
            <div>
              {steps.map((step, i) => (
                <TimelineStep key={i} num={step.num} text={step.text} isLast={i === steps.length - 1} />
              ))}
            </div>
          </div>
        )}

        {/* Root Cause Callout */}
        {rootText && (
          <div className="rounded-lg border-l-4 border-l-primary bg-primary/5 p-3">
            <p className="text-xs font-medium uppercase tracking-wide text-primary mb-1">Root Cause</p>
            <p className="text-sm leading-relaxed">{rootText}</p>
          </div>
        )}

        {/* Timeline Gaps */}
        {timelineGaps && timelineGaps.lines.length > 0 && (
          <div className="rounded-lg border bg-muted/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Clock className="h-4 w-4 text-muted-foreground" />
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Timeline Analysis</p>
            </div>
            <p className="text-sm text-muted-foreground">{timelineGaps.lines.join(" ").trim()}</p>
          </div>
        )}

        {/* Threat Intelligence */}
        {(Object.keys(threatKv).length > 0 || mitreMatches.length > 0 || ipMatches.length > 0) && (
          <div>
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground mb-3">Threat Intelligence</p>

            {/* Key-Value pairs as structured items */}
            {Object.keys(threatKv).length > 0 && (
              <div className="space-y-2 mb-3">
                {Object.entries(threatKv).map(([k, v]) => (
                  <div key={k} className="flex items-start gap-2 rounded-md border p-2.5 bg-muted/20">
                    <span className="text-xs font-medium text-muted-foreground shrink-0 w-36">{k}</span>
                    <span className="text-sm min-w-0">{v}</span>
                  </div>
                ))}
              </div>
            )}

            {/* MITRE badges */}
            {mitreMatches.length > 0 && (
              <div className="mb-3">
                <p className="text-xs text-muted-foreground mb-1.5">MITRE Techniques</p>
                <div className="flex flex-wrap gap-1.5">
                  {[...new Set(mitreMatches)].map((t) => (
                    <Badge key={t} variant="secondary" className="text-xs font-mono cursor-pointer hover:bg-primary/20" onClick={() => router.push(`/search?q=${encodeURIComponent(t)}`)}>
                      {t}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* Discovered IPs */}
            {ipMatches.length > 0 && (
              <div className="mb-3">
                <p className="text-xs text-muted-foreground mb-1.5">IP Addresses</p>
                <div className="flex flex-wrap gap-1.5">
                  {[...new Set(ipMatches)].map((ip) => (
                    <div key={ip} className="flex items-center gap-1">
                      <Badge variant="outline" className="font-mono text-xs">
                        <Fingerprint className="h-3 w-3 mr-1" />
                        {ip}
                      </Badge>
                      <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => copyToClipboard(ip)}>
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Discovered Domains */}
            {domainMatches.length > 0 && (
              <div className="mb-3">
                <p className="text-xs text-muted-foreground mb-1.5">Domains</p>
                <div className="flex flex-wrap gap-1.5">
                  {[...new Set(domainMatches)].map((d) => (
                    <Badge key={d} variant="outline" className="text-xs gap-1">
                      <Globe className="h-3 w-3" />
                      {d}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* File paths */}
            {fileMatches.length > 0 && (
              <div>
                <p className="text-xs text-muted-foreground mb-1.5">Files / Paths</p>
                <div className="flex flex-wrap gap-1.5">
                  {[...new Set(fileMatches)].map((f) => (
                    <code key={f} className="bg-muted px-2 py-1 rounded text-xs font-mono">{f}</code>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Asset Inventory */}
        {Object.keys(assetKv).length > 0 && (
          <div>
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground mb-2">Asset Inventory</p>
            <div className="rounded-lg border p-3 space-y-2">
              {Object.entries(assetKv).map(([k, v]) => (
                <div key={k} className="flex items-start gap-2">
                  <Server className="h-4 w-4 text-muted-foreground shrink-0 mt-0.5" />
                  <div>
                    <span className="text-xs font-medium text-muted-foreground">{k}</span>
                    <p className="text-sm">{v}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
