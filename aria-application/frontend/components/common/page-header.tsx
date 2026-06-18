"use client";

import { Button } from "@/components/ui/button";
import { RefreshCw, ArrowLeft } from "lucide-react";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/utils";

interface PageHeaderProps {
  title: string;
  description?: React.ReactNode;
  onRefresh?: () => void;
  isLoading?: boolean;
  actions?: React.ReactNode;
  isLive?: boolean;
  badge?: React.ReactNode;
  icon?: React.ElementType;
  backHref?: string;
  backLabel?: string;
}

export function PageHeader({
  title,
  description,
  onRefresh,
  isLoading,
  actions,
  isLive,
  badge,
  icon: Icon,
  backHref,
  backLabel,
}: PageHeaderProps) {
  const router = useRouter();

  return (
    <header className="sticky top-0 z-10 border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/70">
      <div className="flex min-h-16 flex-wrap items-center justify-between gap-x-4 gap-y-2 px-6 py-2.5">
        <div className="flex items-center gap-3">
          {backHref !== undefined && (
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-muted-foreground hover:text-foreground shrink-0"
              onClick={() => backHref ? router.push(backHref) : router.back()}
              aria-label={backLabel || "Go back"}
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          {Icon && (
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary ring-1 ring-inset ring-primary/20">
              <Icon className="h-5 w-5" />
            </div>
          )}
          <div className="min-w-0">
            <div className="flex items-center gap-2.5">
              <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
              {isLive && (
                <span className="flex items-center gap-1.5 rounded-full bg-success/10 px-2 py-0.5 text-xs font-medium text-success">
                  <span className="relative flex h-2 w-2">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-75" />
                    <span className="relative inline-flex h-2 w-2 rounded-full bg-success" />
                  </span>
                  Live
                </span>
              )}
              {badge}
            </div>
            {description && (
              <p className="mt-0.5 text-sm text-muted-foreground">{description}</p>
            )}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2.5">
          {actions}
          {onRefresh && (
            <Button
              variant="outline"
              size="icon"
              onClick={onRefresh}
              disabled={isLoading}
              aria-label="Refresh"
              className="relative"
            >
              <RefreshCw className={cn("h-4 w-4", isLoading && "animate-spin")} />
            </Button>
          )}
        </div>
      </div>
    </header>
  );
}
