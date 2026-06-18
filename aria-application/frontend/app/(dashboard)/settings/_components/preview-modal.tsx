"use client";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { SettingsPreviewItem } from "@/lib/api";

interface PreviewModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  preview: SettingsPreviewItem[];
  onConfirm: () => void;
}

function maskValue(value: any): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string" && value.length > 0) {
    // Mask likely secrets
    if (value.length > 8) return "•".repeat(Math.min(value.length, 16));
    return value;
  }
  return String(value);
}

export function PreviewModal({
  open,
  onOpenChange,
  preview,
  onConfirm,
}: PreviewModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Confirm Changes</DialogTitle>
          <DialogDescription>
            Review the changes before applying them.
          </DialogDescription>
        </DialogHeader>
        <div className="max-h-80 overflow-auto py-4">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="py-2 text-left font-medium text-muted-foreground">Setting</th>
                <th className="py-2 text-left font-medium text-muted-foreground">Old</th>
                <th className="py-2 text-left font-medium text-muted-foreground">New</th>
              </tr>
            </thead>
            <tbody>
              {preview.map((item) => (
                <tr key={item.key} className="border-b">
                  <td className="py-2 font-mono text-xs">{item.key}</td>
                  <td className="py-2 text-muted-foreground">{maskValue(item.old)}</td>
                  <td className="py-2">
                    <div className="flex items-center gap-2">
                      <span>{maskValue(item.new)}</span>
                      <Badge variant="outline" className="text-xs">
                        {item.type}
                      </Badge>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={onConfirm}>Proceed to Admin Secret</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
