import { cn } from "@/lib/utils";

interface SectionHeaderProps {
  /** Uppercase section label, e.g. "SOC Overview". */
  title: string;
  /** Optional supporting text shown under the title. */
  description?: string;
  /** Optional right-aligned content — controls, links, counts. */
  action?: React.ReactNode;
  className?: string;
}

/**
 * Lightweight section divider for grouping content within a page.
 * Renders a small uppercase label, an optional description, and a hairline
 * rule that fills the remaining width — standardizing the section headings
 * used across the dashboard and detail pages.
 */
export function SectionHeader({
  title,
  description,
  action,
  className,
}: SectionHeaderProps) {
  return (
    <div className={cn("mb-3", className)}>
      <div className="flex items-center gap-3">
        <span className="text-xs font-bold uppercase tracking-widest text-muted-foreground">
          {title}
        </span>
        <div className="h-px flex-1 bg-border/50" />
        {action && (
          <div className="flex shrink-0 items-center gap-2">{action}</div>
        )}
      </div>
      {description && (
        <p className="mt-1 text-xs text-muted-foreground">{description}</p>
      )}
    </div>
  );
}
