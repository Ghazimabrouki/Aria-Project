"use client";

import { useState } from "react";
import { Terminal, Copy, Check } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

interface PlaybookViewerProps {
  yaml: string;
}

export function PlaybookViewer({ yaml }: PlaybookViewerProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(yaml);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Simple syntax coloring via regex replacement
  const coloredYaml = yaml
    .replace(/^(---)/gm, '<span class="text-muted-foreground">$1</span>')
    .replace(/^(- name:)(.*)$/gm, '<span class="text-blue-400">$1</span><span class="text-foreground">$2</span>')
    .replace(/^(  hosts:)(.*)$/gm, '<span class="text-purple-400">$1</span><span class="text-foreground">$2</span>')
    .replace(/^(  become:)(.*)$/gm, '<span class="text-purple-400">$1</span><span class="text-foreground">$2</span>')
    .replace(/^(  tasks:)$/gm, '<span class="text-purple-400">$1</span>')
    .replace(/^(    - name:)(.*)$/gm, '<span class="text-emerald-400">$1</span><span class="text-foreground">$2</span>')
    .replace(/^(      ansible\.builtin\.\w+:)(.*)$/gm, '<span class="text-amber-400">$1</span><span class="text-foreground">$2</span>')
    .replace(/^(      register:)(.*)$/gm, '<span class="text-cyan-400">$1</span><span class="text-foreground">$2</span>')
    .replace(/^(      changed_when:)(.*)$/gm, '<span class="text-cyan-400">$1</span><span class="text-foreground">$2</span>')
    .replace(/^(      failed_when:)(.*)$/gm, '<span class="text-cyan-400">$1</span><span class="text-foreground">$2</span>')
    .replace(/^(      when:)(.*)$/gm, '<span class="text-cyan-400">$1</span><span class="text-foreground">$2</span>')
    .replace(/^(      vars:)$/gm, '<span class="text-purple-400">$1</span>')
    .replace(/^(      msg:)(.*)$/gm, '<span class="text-cyan-400">$1</span><span class="text-green-400">$2</span>');

  return (
    <Card>
      <CardHeader className="pb-3 flex flex-row items-center justify-between">
        <CardTitle className="text-base flex items-center gap-2">
          <Terminal className="h-4 w-4 text-primary" />
          Ansible Playbook
        </CardTitle>
        <Button variant="ghost" size="sm" className="h-8 gap-1.5" onClick={handleCopy}>
          {copied ? (
            <>
              <Check className="h-3.5 w-3.5 text-success" />
              <span className="text-success">Copied</span>
            </>
          ) : (
            <>
              <Copy className="h-3.5 w-3.5" />
              <span>Copy</span>
            </>
          )}
        </Button>
      </CardHeader>
      <CardContent>
        <div className="rounded-lg bg-muted/50 border overflow-hidden">
          <pre
            className="p-4 overflow-x-auto text-sm font-mono leading-relaxed"
            dangerouslySetInnerHTML={{ __html: coloredYaml }}
          />
        </div>
      </CardContent>
    </Card>
  );
}
