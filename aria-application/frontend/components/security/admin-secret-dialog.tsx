"use client";

import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ShieldAlert } from "lucide-react";

interface AdminSecretDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: (secret: string) => void;
  title?: string;
  description?: string;
  error?: string | null;
}

export function AdminSecretDialog({
  open,
  onOpenChange,
  onConfirm,
  title = "Unlock Admin Session",
  description = "This action requires admin privileges. Please enter the admin secret to continue.",
  error,
}: AdminSecretDialogProps) {
  const [secret, setSecret] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);
    const trimmed = secret.trim();
    if (!trimmed) {
      setValidationError("Admin secret is required.");
      return;
    }
    if (trimmed.length < 4) {
      setValidationError("Secret is too short.");
      return;
    }
    onConfirm(trimmed);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-destructive" />
              {title}
            </DialogTitle>
            <DialogDescription>{description}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <label htmlFor="admin-secret" className="text-sm font-medium">
                Admin Secret
              </label>
              <Input
                id="admin-secret"
                type="password"
                placeholder="Enter X-ARIA-Admin-Secret"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                autoFocus
              />
              {validationError && (
                <p className="text-xs text-destructive">{validationError}</p>
              )}
              {error && (
                <p className="text-xs text-destructive">{error}</p>
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              The admin secret is stored only in memory and will be cleared when you refresh the page.
            </p>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit">Continue</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
