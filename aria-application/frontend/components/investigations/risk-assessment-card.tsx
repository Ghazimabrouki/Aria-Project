"use client";

import {
  AlertTriangle,
  Shield,
  CheckCircle2,
  Copy,
  Search,
  Server,
  Eye,
  Fingerprint,
  TrendingUp,
  ChevronDown,
  ChevronUp,
  Activity,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { cn } from "@/lib/utils";

interface RiskAssessmentCardProps {
  text: string;
}

function extractJsonBlock(text: string): Record<string, unknown> | null {
  const match = text.match(/STRUCTURED METADATA \(JSON\)\s*({[\s\S]*})/i);
  if (!match) return null;
  try {
    return JSON.parse(match[1]);
  } catch {
    return null;
  }
}

function extractRiskLevel(text: string): string | null {
  const m = text.match(/risk level[:\s]*(\w+)/i);
  return m ? m[1].toUpperCase() : null;
}

function extractRiskScore(text: string): number | null {
  const m = text.match(/risk score[:\s]*(\d+)/i);
  return m ? parseInt(m[1], 10) : null;
}

function riskStyles(level: string) {
  switch (level) {
    case "CRITICAL":
      return {
        badge: "bg-red-600 text-white border-red-700",
        border: "border-red-300 dark:border-red-800",
        bar: "bg-red-600",
        lightBg: "bg-red-50 dark:bg-red-950/20",
        text: "text-red-700 dark:text-red-300",
        icon: "text-red-600",
        gauge: "text-red-600",
      };
    case "HIGH":
      return {
        badge: "bg-orange-500 text-white border-orange-600",
        border: "border-orange-300 dark:border-orange-800",
        bar: "bg-orange-500",
        lightBg: "bg-orange-50 dark:bg-orange-950/20",
        text: "text-orange-700 dark:text-orange-300",
        icon: "text-orange-600",
        gauge: "text-orange-500",
      };
    case "MEDIUM":
      return {
        badge: "bg-amber-500 text-white border-amber-600",
        border: "border-amber-300 dark:border-amber-800",
        bar: "bg-amber-500",
        lightBg: "bg-amber-50 dark:bg-amber-950/20",
        text: "text-amber-700 dark:text-amber-300",
        icon: "text-amber-600",
        gauge: "text-amber-500",
      };
    case "LOW":
      return {
        badge: "bg-blue-500 text-white border-blue-600",
        border: "border-blue-300 dark:border-blue-800",
        bar: "bg-blue-500",
        lightBg: "bg-blue-50 dark:bg-blue-950/20",
        text: "text-blue-700 dark:text-blue-300",
        icon: "text-blue-600",
        gauge: "text-blue-500",
      };
    default:
      return {
        badge: "bg-slate-500 text-white border-slate-600",
        border: "border-border",
        bar: "bg-slate-500",
        lightBg: "bg-muted/30",
        text: "text-muted-foreground",
        icon: "text-muted-foreground",
        gauge: "text-muted-foreground",
      };
  }
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
    if (line.startsWith("STRUCTURED METADATA")) break;
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

function parseList(lines: string[]): string[] {
  return lines
    .map((l) => l.trim())
    .filter((l) => l.startsWith("-") || l.startsWith("*") || /^\d+\./.test(l))
    .map((l) => l.replace(/^\s*[-*\d.]+\s*/, "").trim());
}

function ImpactCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: string;
  icon: React.ElementType;
  color: string;
}) {
  return (
    <div className={`rounded-md border p-2.5 ${color}`}>
      <div className="flex items-center gap-1.5 mb-1">
        <Icon className="h-3.5 w-3.5 opacity-70" />
        <span className="text-[11px] font-medium uppercase tracking-wide opacity-80">
          {label}
        </span>
      </div>
      <p className="text-xs font-semibold">{value}</p>
    </div>
  );
}

/* ─── Compact Risk Gauge ─── */
function RiskGauge({
  level,
  score,
}: {
  level: string;
  score: number | null;
}) {
  const styles = riskStyles(level);
  const displayScore = score ?? (level === "CRITICAL" ? 90 : level === "HIGH" ? 75 : level === "MEDIUM" ? 50 : 20);

  return (
    <div className="flex items-center gap-4">
      {/* Circular indicator */}
      <div className="relative flex items-center justify-center">
        <svg className="h-14 w-14 -rotate-90" viewBox="0 0 36 36">
          <path
            className="text-muted/20"
            d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            fill="none"
            stroke="currentColor"
            strokeWidth="3"
          />
          <path
            className={styles.gauge}
            d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            fill="none"
            stroke="currentColor"
            strokeWidth="3"
            strokeDasharray={`${displayScore}, 100`}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn("text-[10px] font-bold leading-none", styles.text)}>
            {displayScore}
          </span>
          <span className="text-[8px] text-muted-foreground uppercase">/100</span>
        </div>
      </div>

      {/* Level + label */}
      <div className="flex flex-col gap-0.5">
        <Badge className={`${styles.badge} text-[10px] uppercase tracking-wider w-fit`}>
          {level}
        </Badge>
        <span className="text-[11px] text-muted-foreground">
          {level === "CRITICAL"
            ? "Immediate action required"
            : level === "HIGH"
            ? "Address as soon as possible"
            : level === "MEDIUM"
            ? "Review during next cycle"
            : "Low priority — monitor"}
        </span>
      </div>
    </div>
  );
}

export function RiskAssessmentCard({ text }: RiskAssessmentCardProps) {
  const router = useRouter();
  const [expanded, setExpanded] = useState(false);

  const riskLevel = extractRiskLevel(text);
  const riskScore = extractRiskScore(text);
  const meta = extractJsonBlock(text);
  const sections = parseSections(text);

  const impactSection = sections.find((s) =>
    s.title.toLowerCase().includes("impact")
  );
  const confidenceSection = sections.find((s) =>
    s.title.toLowerCase().includes("confidence")
  );
  const verificationSection = sections.find((s) =>
    s.title.toLowerCase().includes("verification")
  );

  const impactKv = impactSection ? parseKeyValue(impactSection.lines) : {};
  const confidenceKv = confidenceSection
    ? parseKeyValue(confidenceSection.lines)
    : {};
  const verificationItems = verificationSection
    ? parseList(verificationSection.lines)
    : [];

  const copyToClipboard = (t: string) => navigator.clipboard.writeText(t);

  const styles = riskStyles(riskLevel || "");

  // Determine if we have "rich" content beyond just the risk level
  const hasRichContent =
    meta ||
    Object.keys(impactKv).length > 0 ||
    Object.keys(confidenceKv).length > 0 ||
    verificationItems.length > 0;

  return (
    <Card className={cn(`${styles.border} overflow-hidden`, styles.lightBg)}>
      <CardHeader className="pb-0 pt-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className={`h-4 w-4 ${styles.icon}`} />
            <CardTitle className="text-sm font-medium">Risk Assessment</CardTitle>
          </div>
          {hasRichContent && (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 text-xs gap-1 text-muted-foreground"
              onClick={() => setExpanded((v) => !v)}
            >
              {expanded ? (
                <>
                  Less <ChevronUp className="h-3 w-3" />
                </>
              ) : (
                <>
                  More <ChevronDown className="h-3 w-3" />
                </>
              )}
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-4 pt-3 pb-4">
        {/* Always-visible compact gauge */}
        <RiskGauge level={riskLevel || "UNKNOWN"} score={riskScore} />

        {/* Always-visible top-level badges row */}
        {meta && (
          <div className="flex flex-wrap gap-1.5">
            {typeof meta.compromised === "boolean" && (
              <Badge
                variant={meta.compromised ? "destructive" : "outline"}
                className="gap-1 text-[10px]"
              >
                {meta.compromised ? (
                  <Shield className="h-2.5 w-2.5" />
                ) : (
                  <Eye className="h-2.5 w-2.5" />
                )}
                {meta.compromised ? "Compromised" : "Not Compromised"}
              </Badge>
            )}
            {!!meta.attack_type && (
              <Badge variant="outline" className="capitalize text-[10px]">
                {String(meta.attack_type).replace(/_/g, " ")}
              </Badge>
            )}
            {!!meta.investigation_quality && (
              <Badge
                variant="outline"
                className="capitalize text-[10px] text-emerald-600 border-emerald-300"
              >
                {String(meta.investigation_quality)}
              </Badge>
            )}
          </div>
        )}

        {/* Expandable rich content */}
        {hasRichContent && expanded && (
          <div className="space-y-4 pt-2 border-t">
            {/* Risk Score Bar (if not already shown in gauge) */}
            {meta && typeof meta.risk_score === "number" && !riskScore && (
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-medium">Risk Score</span>
                  <span className="text-xs font-bold">{meta.risk_score}/100</span>
                </div>
                <Progress value={meta.risk_score} className="h-1.5" />
              </div>
            )}

            {/* Impact Assessment Grid */}
            {Object.keys(impactKv).length > 0 && (
              <div>
                <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground mb-1.5">
                  Impact Assessment
                </p>
                <div className="grid grid-cols-2 gap-2">
                  {impactKv["Confidentiality"] && (
                    <ImpactCard
                      label="Confidentiality"
                      value={impactKv["Confidentiality"]}
                      icon={Eye}
                      color="border-purple-200 bg-purple-50 text-purple-900 dark:bg-purple-950/30 dark:text-purple-300 dark:border-purple-900"
                    />
                  )}
                  {impactKv["Integrity"] && (
                    <ImpactCard
                      label="Integrity"
                      value={impactKv["Integrity"]}
                      icon={Shield}
                      color="border-emerald-200 bg-emerald-50 text-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-300 dark:border-emerald-900"
                    />
                  )}
                  {impactKv["Availability"] && (
                    <ImpactCard
                      label="Availability"
                      value={impactKv["Availability"]}
                      icon={Server}
                      color="border-blue-200 bg-blue-50 text-blue-900 dark:bg-blue-950/30 dark:text-blue-300 dark:border-blue-900"
                    />
                  )}
                  {impactKv["Business impact"] && (
                    <ImpactCard
                      label="Business Impact"
                      value={impactKv["Business impact"]}
                      icon={TrendingUp}
                      color="border-amber-200 bg-amber-50 text-amber-900 dark:bg-amber-950/30 dark:text-amber-300 dark:border-amber-900"
                    />
                  )}
                </div>
              </div>
            )}

            {/* Confidence Scoring */}
            {Object.keys(confidenceKv).length > 0 && (
              <div>
                <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground mb-1.5">
                  Confidence
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(confidenceKv).map(([k, v]) => (
                    <Badge
                      key={k}
                      variant="outline"
                      className="gap-1 capitalize text-[10px]"
                    >
                      <CheckCircle2 className="h-2.5 w-2.5 text-emerald-500" />
                      {k.replace(/_/g, " ")}: {v}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* MITRE Techniques */}
            {meta &&
              Array.isArray(meta.mitre_techniques) &&
              meta.mitre_techniques.length > 0 && (
                <div>
                  <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground mb-1.5">
                    MITRE ATT&CK
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {meta.mitre_techniques.map((t) => (
                      <Badge
                        key={String(t)}
                        variant="secondary"
                        className="text-[10px] font-mono cursor-pointer hover:bg-primary/20"
                        onClick={() =>
                          router.push(
                            `/search?q=${encodeURIComponent(String(t))}`
                          )
                        }
                      >
                        {String(t)}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

            {/* Assets */}
            {meta &&
              Array.isArray(meta.affected_assets) &&
              meta.affected_assets.length > 0 && (
                <div>
                  <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground mb-1.5">
                    Affected Assets
                  </p>
                  <div className="space-y-1.5">
                    {meta.affected_assets.map((asset: any, idx: number) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between rounded-md border p-2 bg-background/60"
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <Server className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                          <div className="min-w-0">
                            <p className="text-xs font-medium truncate">
                              {asset.host || "Unknown"}
                            </p>
                            <p className="text-[10px] text-muted-foreground">
                              {asset.ip || "—"}{" "}
                              {asset.role ? `· ${asset.role}` : ""}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          {asset.compromised && (
                            <Badge
                              variant="destructive"
                              className="text-[9px] px-1 py-0"
                            >
                              Compromised
                            </Badge>
                          )}
                          {asset.confidence && (
                            <Badge
                              variant="outline"
                              className="text-[9px] px-1 py-0 capitalize"
                            >
                              {asset.confidence}
                            </Badge>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            {/* Attacker / Target IPs */}
            {meta &&
              (Array.isArray(meta.attacker_ips) ||
                Array.isArray(meta.target_ips)) && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {Array.isArray(meta.attacker_ips) &&
                    meta.attacker_ips.length > 0 && (
                      <div className="rounded-md border p-2.5 bg-background/60">
                        <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground mb-1">
                          Attacker IPs
                        </p>
                        <div className="flex flex-wrap gap-1">
                          {meta.attacker_ips.map((ip: string) => (
                            <div key={ip} className="flex items-center gap-0.5">
                              <Badge
                                variant="destructive"
                                className="font-mono text-[10px] gap-1 px-1.5 py-0"
                              >
                                <Fingerprint className="h-2.5 w-2.5" />
                                {ip}
                              </Badge>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-5 w-5"
                                onClick={() => copyToClipboard(ip)}
                              >
                                <Copy className="h-2.5 w-2.5" />
                              </Button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  {Array.isArray(meta.target_ips) &&
                    meta.target_ips.length > 0 && (
                      <div className="rounded-md border p-2.5 bg-background/60">
                        <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground mb-1">
                          Target IPs
                        </p>
                        <div className="flex flex-wrap gap-1">
                          {meta.target_ips.map((ip: string) => (
                            <div key={ip} className="flex items-center gap-0.5">
                              <Badge
                                variant="outline"
                                className="font-mono text-[10px] gap-1 px-1.5 py-0"
                              >
                                <Server className="h-2.5 w-2.5" />
                                {ip}
                              </Badge>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-5 w-5"
                                onClick={() => copyToClipboard(ip)}
                              >
                                <Copy className="h-2.5 w-2.5" />
                              </Button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                </div>
              )}

            {/* Recommended Actions */}
            {meta &&
              Array.isArray(meta.recommended_actions) &&
              meta.recommended_actions.length > 0 && (
                <div>
                  <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground mb-1.5">
                    Recommended Actions
                  </p>
                  <ul className="space-y-1">
                    {meta.recommended_actions.map((action: string, i: number) => (
                      <li key={i} className="flex items-start gap-2 text-xs">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0 mt-0.5" />
                        <span>{action}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

            {/* Verification Checklist */}
            {verificationItems.length > 0 && (
              <div className="rounded-md border bg-background/60 p-2.5">
                <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground mb-1.5">
                  Verification Steps
                </p>
                <ul className="space-y-1">
                  {verificationItems.map((item, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs">
                      <CheckCircle2 className="h-3.5 w-3.5 text-muted-foreground shrink-0 mt-0.5" />
                      <span className="text-muted-foreground">{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
