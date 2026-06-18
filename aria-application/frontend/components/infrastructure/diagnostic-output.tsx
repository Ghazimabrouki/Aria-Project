"use client";

import { useState } from "react";
import { Terminal, ChevronDown, ChevronUp, Copy, Check } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

interface DiagnosticOutputProps {
  output: string | null;
}

export function DiagnosticOutputCard({ output }: DiagnosticOutputProps) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  if (!output) {
    return (
      <Card className="border-dashed">
        <CardContent className="p-6 text-center text-muted-foreground">
          <Terminal className="mx-auto h-8 w-8 mb-2 opacity-50" />
          <p>Diagnostic output will appear here once the playbook completes.</p>
        </CardContent>
      </Card>
    );
  }

  const handleCopy = async () => {
    await navigator.clipboard.writeText(output);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const previewLines = output.split("\n").slice(0, 8).join("\n");
  const isLong = output.split("\n").length > 8;

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-2">
            <Terminal className="h-4 w-4 text-muted-foreground" />
            Raw Diagnostic Output
          </CardTitle>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1 text-xs"
              onClick={handleCopy}
            >
              {copied ? (
                <Check className="h-3.5 w-3.5" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
              {copied ? "Copied" : "Copy"}
            </Button>
            {isLong && (
              <Button
                variant="ghost"
                size="sm"
                className="h-7 gap-1 text-xs"
                onClick={() => setExpanded(!expanded)}
              >
                {expanded ? (
                  <>
                    <ChevronUp className="h-3.5 w-3.5" /> Collapse
                  </>
                ) : (
                  <>
                    <ChevronDown className="h-3.5 w-3.5" /> Expand
                  </>
                )}
              </Button>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <pre className="text-xs bg-muted rounded-md p-3 overflow-auto max-h-[600px] font-mono leading-relaxed">
          <code>{expanded ? output : previewLines + (isLong ? "\n..." : "")}</code>
        </pre>
        {!expanded && isLong && (
          <p className="text-xs text-muted-foreground mt-2 text-center">
            {output.split("\n").length} lines total — click Expand to view all
          </p>
        )}
      </CardContent>
    </Card>
  );
}
