import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";

interface EmptyStateProps {
  /** Icon shown above the title (Lucide). */
  icon?: LucideIcon;
  title: string;
  description?: React.ReactNode;
  /** Optional action(s) — e.g. a button or link. */
  action?: React.ReactNode;
  /** Show the dashed border + surface tint. Disable when nested inside a card. */
  bordered?: boolean;
  className?: string;
}

/**
 * Standard empty-state placeholder for lists, tables, panels and timelines.
 * Wraps the shadcn <Empty> primitives with a consistent icon + title +
 * description + action layout so every "no data" view looks the same.
 */
export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  bordered = true,
  className,
}: EmptyStateProps) {
  return (
    <Empty
      className={cn(
        bordered && "border bg-card/40",
        "animate-fade-in py-10",
        className
      )}
    >
      <EmptyHeader>
        {Icon && (
          <EmptyMedia variant="icon">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10 ring-1 ring-primary/20">
              <Icon className="size-6 text-primary" aria-hidden="true" />
            </div>
          </EmptyMedia>
        )}
        <EmptyTitle className="text-base font-semibold">{title}</EmptyTitle>
        {description && (
          <EmptyDescription className="max-w-sm mx-auto">
            {description}
          </EmptyDescription>
        )}
      </EmptyHeader>
      {action && <EmptyContent>{action}</EmptyContent>}
    </Empty>
  );
}
