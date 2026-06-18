"use client";

import { useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { Check, Copy, Download, Maximize2, Minimize2 } from "lucide-react";

interface YamlViewerProps {
  yaml: string;
  title?: string;
  maxHeight?: string;
  showLineNumbers?: boolean;
  showCopyButton?: boolean;
  showDownloadButton?: boolean;
  className?: string;
}

export function YamlViewer({
  yaml,
  title,
  maxHeight = "400px",
  showLineNumbers = true,
  showCopyButton = true,
  showDownloadButton = true,
  className,
}: YamlViewerProps) {
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(yaml);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([yaml], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${title?.toLowerCase().replace(/\s+/g, "-") || "playbook"}.yml`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const highlightedYaml = useMemo(() => {
    return yaml.split("\n").map((line, index) => {
      // Apply syntax highlighting
      let highlighted = line;

      // Comments
      if (line.trim().startsWith("#")) {
        highlighted = `<span class="yaml-comment">${escapeHtml(line)}</span>`;
      }
      // Key-value pairs
      else if (line.includes(":")) {
        const colonIndex = line.indexOf(":");
        const key = line.substring(0, colonIndex);
        const value = line.substring(colonIndex + 1);
        
        const highlightedKey = `<span class="yaml-key">${escapeHtml(key)}</span>`;
        const highlightedValue = highlightValue(value);
        
        highlighted = `${highlightedKey}:${highlightedValue}`;
      }
      // List items
      else if (line.trim().startsWith("-")) {
        const dashIndex = line.indexOf("-");
        const prefix = line.substring(0, dashIndex);
        const content = line.substring(dashIndex + 1);
        highlighted = `${prefix}<span class="yaml-key">-</span>${highlightValue(content)}`;
      }

      return {
        number: index + 1,
        content: highlighted,
      };
    });
  }, [yaml]);

  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-lg border bg-muted/30",
        expanded && "fixed inset-4 z-50 bg-background",
        className
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b bg-muted/50 px-4 py-2">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <div className="h-3 w-3 rounded-full bg-destructive/60" />
            <div className="h-3 w-3 rounded-full bg-warning/60" />
            <div className="h-3 w-3 rounded-full bg-success/60" />
          </div>
          {title && (
            <span className="ml-2 font-mono text-sm text-muted-foreground">
              {title}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          {showCopyButton && (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 w-7 p-0"
              onClick={handleCopy}
            >
              {copied ? (
                <Check className="h-3.5 w-3.5 text-success" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </Button>
          )}
          {showDownloadButton && (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 w-7 p-0"
              onClick={handleDownload}
            >
              <Download className="h-3.5 w-3.5" />
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            className="h-7 w-7 p-0"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? (
              <Minimize2 className="h-3.5 w-3.5" />
            ) : (
              <Maximize2 className="h-3.5 w-3.5" />
            )}
          </Button>
        </div>
      </div>

      {/* Code content */}
      <ScrollArea
        className="yaml-viewer"
        style={{ maxHeight: expanded ? "calc(100vh - 120px)" : maxHeight }}
      >
        <div className="p-4">
          <table className="w-full border-collapse">
            <tbody>
              {highlightedYaml.map((line) => (
                <tr key={line.number} className="hover:bg-muted/30">
                  {showLineNumbers && (
                    <td className="select-none pr-4 text-right text-muted-foreground/50 w-[1%] whitespace-nowrap">
                      {line.number}
                    </td>
                  )}
                  <td className="whitespace-pre">
                    <span dangerouslySetInnerHTML={{ __html: line.content }} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </ScrollArea>

      {/* Expanded overlay */}
      {expanded && (
        <div
          className="fixed inset-0 -z-10 bg-background/80 backdrop-blur-sm"
          onClick={() => setExpanded(false)}
        />
      )}
    </div>
  );
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function highlightValue(value: string): string {
  const trimmed = value.trim();
  
  // Empty value
  if (!trimmed) {
    return escapeHtml(value);
  }
  
  // Strings in quotes
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return `<span class="yaml-string">${escapeHtml(value)}</span>`;
  }
  
  // Booleans
  if (['true', 'false', 'yes', 'no', 'on', 'off'].includes(trimmed.toLowerCase())) {
    return `<span class="yaml-value">${escapeHtml(value)}</span>`;
  }
  
  // Numbers
  if (!isNaN(Number(trimmed))) {
    return `<span class="yaml-number">${escapeHtml(value)}</span>`;
  }
  
  // Regular values
  return `<span class="yaml-value">${escapeHtml(value)}</span>`;
}
