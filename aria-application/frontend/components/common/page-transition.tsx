"use client";

import { usePathname } from "next/navigation";

/**
 * Wraps routed page content and replays a subtle enter animation on every
 * navigation (keyed by pathname). Gives the app a smooth, cohesive feel
 * between pages. Honors `prefers-reduced-motion` via globals.css.
 */
export function PageTransition({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  return (
    <div key={pathname} className="animate-page-enter h-full">
      {children}
    </div>
  );
}
