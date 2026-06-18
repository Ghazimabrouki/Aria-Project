"use client";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { AlertTriangle, RefreshCw, WifiOff } from "lucide-react";

interface ErrorStateProps {
  /** Optional explicit heading. Defaults are derived from the error type. */
  title?: string;
  /** The error — an Error object, a message string, or any object with `.message`. */
  error?: unknown;
  /** Retry handler — renders a "Try again" button when provided. */
  onRetry?: () => void;
  /** Show the border + surface tint. Disable when nested inside a card. */
  bordered?: boolean;
  className?: string;
}

function errorMessage(error: unknown): string {
  if (!error) return "";
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  if (typeof error === "object" && "message" in error) {
    return String((error as { message?: unknown }).message ?? "");
  }
  return "";
}

function isNetworkError(message: string): boolean {
  const m = message.toLowerCase();
  return (
    m.includes("network") ||
    m.includes("failed to fetch") ||
    m.includes("fetch failed") ||
    m.includes("connection") ||
    m.includes("econnrefused") ||
    m.includes("timeout")
  );
}

/**
 * Standard error placeholder for failed data loads. Distinguishes network
 * errors (backend unreachable) from generic errors and offers a retry action.
 */
export function ErrorState({
  title,
  error,
  onRetry,
  bordered = true,
  className,
}: ErrorStateProps) {
  const message = errorMessage(error);
  const network = isNetworkError(message);
  const Icon = network ? WifiOff : AlertTriangle;
  const heading =
    title ?? (network ? "Can't reach the ARIA backend" : "Something went wrong");
  const detail =
    message ||
    (network
      ? "The ARIA service didn't respond. Check that it's running, then try again."
      : "An unexpected error occurred while loading this data.");

  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-center justify-center gap-4 rounded-lg p-8 text-center",
        bordered && "border border-destructive/30 bg-destructive/5",
        className,
      )}
    >
      <div className="flex size-12 items-center justify-center rounded-full bg-destructive/10 text-destructive">
        <Icon className="size-6" aria-hidden="true" />
      </div>
      <div className="space-y-1">
        <p className="font-medium text-foreground">{heading}</p>
        <p className="mx-auto max-w-md text-sm text-muted-foreground">{detail}</p>
      </div>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw className="size-4" aria-hidden="true" />
          Try again
        </Button>
      )}
    </div>
  );
}
