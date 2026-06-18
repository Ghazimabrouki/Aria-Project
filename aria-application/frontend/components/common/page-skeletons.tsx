"use client";

import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/** Dashboard skeleton with stat cards + chart placeholders */
export function DashboardSkeleton() {
  return (
    <div className="space-y-6 p-6 animate-fade-in">
      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={i} className="border">
            <CardHeader className="pb-2">
              <Skeleton className="h-4 w-24" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-8 w-16 mb-2" />
              <Skeleton className="h-3 w-32" />
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-2 border">
          <CardHeader className="pb-2">
            <Skeleton className="h-4 w-32" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-[200px] w-full rounded-lg" />
          </CardContent>
        </Card>
        <Card className="border">
          <CardHeader className="pb-2">
            <Skeleton className="h-4 w-28" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-[200px] w-full rounded-lg" />
          </CardContent>
        </Card>
      </div>

      {/* Bottom widgets */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {Array.from({ length: 2 }).map((_, i) => (
          <Card key={i} className="border">
            <CardHeader className="pb-2">
              <Skeleton className="h-4 w-36" />
            </CardHeader>
            <CardContent className="space-y-3">
              <Skeleton className="h-3 w-full" />
              <Skeleton className="h-3 w-[80%]" />
              <Skeleton className="h-3 w-[60%]" />
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

/** List page skeleton with filters + table */
export function ListPageSkeleton({ filterCount = 4 }: { filterCount?: number }) {
  return (
    <div className="space-y-4 p-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-7 w-40" />
          <Skeleton className="h-4 w-56" />
        </div>
        <Skeleton className="h-9 w-9 rounded-md" />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        {Array.from({ length: filterCount }).map((_, i) => (
          <Skeleton key={i} className="h-9 w-[140px] rounded-md" />
        ))}
        <Skeleton className="h-9 w-24 rounded-md" />
      </div>

      {/* Table */}
      <div className="rounded-lg border">
        <div className="border-b bg-muted/50 p-3">
          <div className="flex gap-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-3 w-20" />
            ))}
          </div>
        </div>
        <div className="divide-y">
          {Array.from({ length: 6 }).map((_, rowIdx) => (
            <div key={rowIdx} className="flex items-center gap-4 p-3">
              {Array.from({ length: 5 }).map((_, colIdx) => (
                <Skeleton key={colIdx} className={cn("h-4", colIdx === 0 ? "w-32" : "w-20")} />
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between">
        <Skeleton className="h-4 w-32" />
        <div className="flex gap-2">
          <Skeleton className="h-8 w-20 rounded-md" />
          <Skeleton className="h-8 w-20 rounded-md" />
        </div>
      </div>
    </div>
  );
}

/** Detail page skeleton with header + content cards */
export function DetailPageSkeleton({ sectionCount = 3 }: { sectionCount?: number }) {
  return (
    <div className="space-y-4 p-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Skeleton className="h-10 w-10 rounded-lg" />
          <div className="space-y-2">
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-4 w-32" />
          </div>
        </div>
        <Skeleton className="h-9 w-9 rounded-md" />
      </div>

      {/* Content sections */}
      {Array.from({ length: sectionCount }).map((_, i) => (
        <Card key={i} className="border">
          <CardHeader className="pb-2">
            <Skeleton className="h-5 w-32" />
          </CardHeader>
          <CardContent className="space-y-3">
            <Skeleton className="h-3 w-full" />
            <Skeleton className="h-3 w-[90%]" />
            <Skeleton className="h-3 w-[75%]" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

/** Settings page skeleton with card grid */
export function SettingsPageSkeleton({ cardCount = 9 }: { cardCount?: number }) {
  return (
    <div className="space-y-4 p-6 animate-fade-in">
      <div className="space-y-2">
        <Skeleton className="h-7 w-32" />
        <Skeleton className="h-4 w-64" />
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {Array.from({ length: cardCount }).map((_, i) => (
          <Card key={i} className="border">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-4 w-4" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-7 w-24 mb-2" />
              <Skeleton className="h-3 w-32" />
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

/** Generic card grid skeleton */
export function CardGridSkeleton({ count = 6, columns = 3 }: { count?: number; columns?: number }) {
  return (
    <div className={cn("grid gap-4", columns === 3 && "grid-cols-1 sm:grid-cols-2 lg:grid-cols-3", columns === 2 && "grid-cols-1 md:grid-cols-2")}>
      {Array.from({ length: count }).map((_, i) => (
        <Card key={i} className="border">
          <CardHeader className="pb-2">
            <Skeleton className="h-4 w-28" />
          </CardHeader>
          <CardContent className="space-y-2">
            <Skeleton className="h-6 w-16" />
            <Skeleton className="h-3 w-full" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

/** Simple text skeleton for minimal pages */
export function TextSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="space-y-2 animate-fade-in">
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className={cn("h-4", i === lines - 1 ? "w-[60%]" : "w-full")} />
      ))}
    </div>
  );
}
