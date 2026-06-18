"use client";

import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface AdminSecretModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: (secret: string) => void;
  title?: string;
  description?: string;
}

export function AdminSecretModal({
  open,
  onOpenChange,
  onConfirm,
  title = "Admin Secret Required",
  description = "Enter the admin secret to proceed.",
}: AdminSecretModalProps) {
  const [secret, setSecret] = useState("");

  const handleConfirm = () => {
    if (!secret.trim()) return;
    onConfirm(secret.trim());
    setSecret("");
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Label htmlFor="admin-secret">Admin Secret</Label>
            <Input
              id="admin-secret"
              type="password"
              placeholder="Enter admin secret..."
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleConfirm();
              }}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleConfirm} disabled={!secret.trim()}>
            Confirm
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
