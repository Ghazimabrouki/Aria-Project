"use client";

import { useEffect, useState } from "react";
import { AdminSecretDialog } from "@/components/admin-secret-dialog";
import {
  resolveAdminSecretRequest,
  rejectAdminSecretRequest,
} from "@/lib/admin-secret";

export function GlobalAdminSecretDialog() {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const handler = (e: CustomEvent) => {
      setError(e.detail?.errorMessage || null);
      setOpen(true);
    };
    window.addEventListener(
      "aria:admin-secret-required",
      handler as EventListener
    );
    return () => {
      window.removeEventListener(
        "aria:admin-secret-required",
        handler as EventListener
      );
    };
  }, []);

  const handleConfirm = (secret: string) => {
    setOpen(false);
    setError(null);
    resolveAdminSecretRequest(secret);
  };

  const handleOpenChange = (open: boolean) => {
    setOpen(open);
    if (!open) {
      setError(null);
      rejectAdminSecretRequest("Admin secret required.");
    }
  };

  return (
    <AdminSecretDialog
      open={open}
      onOpenChange={handleOpenChange}
      onConfirm={handleConfirm}
      error={error}
    />
  );
}
