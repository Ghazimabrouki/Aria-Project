"use client";

import { useState, useEffect, Suspense, useRef, useCallback } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import useSWR from "swr";
import { formatDistanceToNow } from "date-fns";
import {
  Search,
  AlertTriangle,
  FileWarning,
  Archive,
  X,
  Filter,
  ChevronDown,
  Clock,
} from "lucide-react";
import { searchAPI, type SearchResponse, type SearchResult } from "@/lib/api";
import { useSelectedAsset } from "@/lib/asset-context";
import { PageHeader } from "@/components/page-header";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { cn } from "@/lib/utils";

const typeIcons: Record<string, React.ElementType> = {
  alert: AlertTriangle,
  incident: FileWarning,
  investigation: Search,
  archive: Archive,
};

const typeColors: Record<string, string> = {
  alert: "text-warning bg-warning/10 border-warning/30",
  incident: "text-destructive bg-destructive/10 border-destructive/30",
  investigation: "text-primary bg-primary/10 border-primary/30",
  archive: "text-muted-foreground bg-muted/10 border-muted/30",
};

const typeRoutes: Record<string, string> = {
  alert: "/alerts",
  incident: "/incidents",
  investigation: "/investigations",
  archive: "/archives",
};

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low"];
const SOURCE_OPTIONS = ["wazuh", "suricata", "filebeat"];

function transformSearchResponse(response: SearchResponse): SearchResult[] {
  const results: SearchResult[] = [];

  response.results.alerts.forEach((alert) => {
    results.push({
      type: "alert",
      id: alert.id,
      title: alert.title || "Untitled Alert",
      description: alert.description || "",
      timestamp: alert.created_at || "",
      relevance: (alert as any).relevance ?? 1.0,
    });
  });

  response.results.incidents.forEach((incident) => {
    results.push({
      type: "incident",
      id: incident.id,
      title: incident.title || "Untitled Incident",
      description: incident.description || "",
      timestamp: incident.created_at || "",
      relevance: (incident as any).relevance ?? 1.0,
    });
  });

  response.results.investigations.forEach((investigation) => {
    results.push({
      type: "investigation",
      id: investigation.id,
      title: investigation.title || `Investigation ${investigation.id}`,
      description: `Status: ${investigation.status || "unknown"}`,
      timestamp: investigation.created_at || "",
      relevance: (investigation as any).relevance ?? 1.0,
    });
  });

  response.results.archives.forEach((archive) => {
    results.push({
      type: "archive",
      id: archive.id,
      title: archive.title || `Archive ${archive.id}`,
      description: `Status: ${archive.status || "unknown"}`,
      timestamp: archive.created_at || "",
      relevance: (archive as any).relevance ?? 1.0,
    });
  });

  return results;
}

function HighlightText({ text, query }: { text: string; query: string }) {
  if (!query || !text) return <>{text}</>;

  // Extract search terms (remove quotes for highlighting)
  const terms = query
    .split(/\s+/)
    .map((t) => t.replace(/^["']|["']$/g, "").replace(/\*$/, ""))
    .filter((t) => t.length > 0);

  if (terms.length === 0) return <>{text}</>;

  const pattern = new RegExp(
    `(${terms.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`,
    "gi"
  );

  const parts = text.split(pattern);

  return (
    <>
      {parts.map((part, i) =>
        terms.some((t) => part.toLowerCase() === t.toLowerCase()) ? (
          <mark key={i} className="bg-yellow-200/60 dark:bg-yellow-700/40 rounded px-0.5">
            {part}
          </mark>
        ) : (
          <span key={i}>{part}</span>
        )
      )}
    </>
  );
}

function SearchPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialQuery = searchParams.get("q") || "";

  const [query, setQuery] = useState(initialQuery);
  const [debouncedQuery, setDebouncedQuery] = useState(initialQuery);
  const [selectedTypes, setSelectedTypes] = useState<string[]>([
    "alert",
    "incident",
    "investigation",
    "archive",
  ]);
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [sourceFilter, setSourceFilter] = useState<string>("");
  const [showFilters, setShowFilters] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  // Load recent searches from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem("recent_searches");
      if (stored) {
        setSuggestions(JSON.parse(stored));
      }
    } catch {
      // ignore
    }
  }, []);

  // Save recent search on debounced query change
  useEffect(() => {
    if (!debouncedQuery.trim()) return;
    setSuggestions((prev) => {
      const updated = [debouncedQuery, ...prev.filter((s) => s !== debouncedQuery)].slice(0, 10);
      try {
        localStorage.setItem("recent_searches", JSON.stringify(updated));
      } catch {
        // ignore
      }
      return updated;
    });
  }, [debouncedQuery]);

  // Debounce search query
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(query);
      setActiveIndex(-1);
    }, 300);
    return () => clearTimeout(timer);
  }, [query]);

  const { selectedAssetId } = useSelectedAsset();

  const { data: rawResults, error, isLoading } = useSWR<SearchResponse>(
    debouncedQuery ? ["search", debouncedQuery, severityFilter, sourceFilter, selectedAssetId] : null,
    () =>
      searchAPI.search(debouncedQuery, 20, {
        severity: severityFilter || undefined,
        source: sourceFilter || undefined,
        asset_id: selectedAssetId || undefined,
      }),
    { revalidateOnFocus: false }
  );

  const results = rawResults ? transformSearchResponse(rawResults) : [];
  const filteredResults = results.filter((r) => selectedTypes.includes(r.type));

  const toggleType = (type: string) => {
    setSelectedTypes((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]
    );
  };

  const handleResultClick = (result: SearchResult) => {
    if (result.type === "alert") {
      router.push(`/alerts?id=${result.id}`);
    } else {
      router.push(`${typeRoutes[result.type]}/${result.id}`);
    }
  };

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Escape") {
        setShowSuggestions(false);
        setActiveIndex(-1);
        if (document.activeElement === inputRef.current) {
          inputRef.current?.blur();
        }
        return;
      }

      if (e.key === "ArrowDown") {
        e.preventDefault();
        if (showSuggestions && suggestions.length > 0) {
          setActiveIndex((prev) => (prev + 1) % suggestions.length);
        } else if (filteredResults.length > 0) {
          setActiveIndex((prev) => Math.min(prev + 1, filteredResults.length - 1));
          resultsRef.current?.children[activeIndex + 1]?.scrollIntoView({ block: "nearest" });
        }
        return;
      }

      if (e.key === "ArrowUp") {
        e.preventDefault();
        if (showSuggestions && suggestions.length > 0 && activeIndex >= 0) {
          setActiveIndex((prev) => (prev <= 0 ? -1 : prev - 1));
        } else if (filteredResults.length > 0) {
          setActiveIndex((prev) => Math.max(prev - 1, -1));
          resultsRef.current?.children[Math.max(activeIndex - 1, 0)]?.scrollIntoView({
            block: "nearest",
          });
        }
        return;
      }

      if (e.key === "Enter") {
        if (showSuggestions && activeIndex >= 0 && suggestions[activeIndex]) {
          setQuery(suggestions[activeIndex]);
          setDebouncedQuery(suggestions[activeIndex]);
          setShowSuggestions(false);
          setActiveIndex(-1);
        } else if (activeIndex >= 0 && filteredResults[activeIndex]) {
          handleResultClick(filteredResults[activeIndex]);
        }
        return;
      }
    },
    [showSuggestions, suggestions, activeIndex, filteredResults, handleResultClick]
  );

  const isRateLimited = error && (error as any).status === 429;

  return (
    <div className="flex flex-col">
      <PageHeader
        title="Search"
        description="Search across all alerts, incidents, investigations, and archives"
      />

      <div className="flex-1 space-y-6 p-6">
        {/* Search Input */}
        <div className="flex items-center gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" />
            <Input
              ref={inputRef}
              placeholder="Search for alerts, incidents, investigations..."
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setShowSuggestions(true);
              }}
              onFocus={() => setShowSuggestions(true)}
              onKeyDown={handleKeyDown}
              className="h-12 pl-10 text-base"
              autoFocus
            />
            {query && (
              <Button
                variant="ghost"
                size="icon"
                className="absolute right-2 top-1/2 h-8 w-8 -translate-y-1/2"
                onClick={() => {
                  setQuery("");
                  setDebouncedQuery("");
                  inputRef.current?.focus();
                }}
              >
                <X className="h-4 w-4" />
              </Button>
            )}

            {/* Suggestions dropdown */}
            {showSuggestions && suggestions.length > 0 && query.length === 0 && (
              <div className="absolute z-10 mt-1 w-full rounded-md border bg-popover shadow-lg">
                <div className="px-3 py-2 text-xs font-medium text-muted-foreground">
                  Recent searches
                </div>
                {suggestions.map((s, i) => (
                  <button
                    key={s}
                    className={cn(
                      "flex w-full items-center gap-2 px-3 py-2 text-sm hover:bg-accent",
                      activeIndex === i && "bg-accent"
                    )}
                    onClick={() => {
                      setQuery(s);
                      setDebouncedQuery(s);
                      setShowSuggestions(false);
                    }}
                  >
                    <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                    {s}
                  </button>
                ))}
              </div>
            )}
          </div>

          <Button
            variant="outline"
            className={cn("h-12 gap-2", showFilters && "bg-accent")}
            onClick={() => setShowFilters((v) => !v)}
          >
            <Filter className="h-4 w-4" />
            Filters
            <ChevronDown
              className={cn("h-3 w-3 transition-transform", showFilters && "rotate-180")}
            />
          </Button>
        </div>

        {/* Advanced Filters */}
        {showFilters && (
          <Card>
            <CardContent className="flex flex-wrap items-center gap-4 py-4">
              <div className="space-y-1">
                <label className="text-xs font-medium text-muted-foreground">Severity</label>
                <select
                  className="h-9 rounded-md border bg-background px-3 text-sm"
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                >
                  <option value="">Any</option>
                  {SEVERITY_OPTIONS.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-muted-foreground">Source</label>
                <select
                  className="h-9 rounded-md border bg-background px-3 text-sm"
                  value={sourceFilter}
                  onChange={(e) => setSourceFilter(e.target.value)}
                >
                  <option value="">Any</option>
                  {SOURCE_OPTIONS.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>

              <Button
                variant="ghost"
                size="sm"
                className="mt-4"
                onClick={() => {
                  setSeverityFilter("");
                  setSourceFilter("");
                }}
              >
                Clear filters
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Type Filters */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Filter className="h-4 w-4" />
            <span>Filter by type:</span>
          </div>
          {["alert", "incident", "investigation", "archive"].map((type) => (
            <label
              key={type}
              className="flex cursor-pointer items-center gap-2"
            >
              <Checkbox
                checked={selectedTypes.includes(type)}
                onCheckedChange={() => toggleType(type)}
              />
              <span className="text-sm capitalize">{type}s</span>
            </label>
          ))}
        </div>

        {/* Results */}
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          </div>
        ) : isRateLimited ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12">
              <AlertTriangle className="h-12 w-12 text-warning" />
              <p className="mt-4 text-lg font-medium">Too many searches</p>
              <p className="text-sm text-muted-foreground">
                Please slow down and try again in a few seconds.
              </p>
            </CardContent>
          </Card>
        ) : error ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12">
              <AlertTriangle className="h-12 w-12 text-destructive" />
              <p className="mt-4 text-lg font-medium">Search failed</p>
              <p className="text-sm text-muted-foreground">
                {(error as any)?.message || "Something went wrong. Please try again."}
              </p>
            </CardContent>
          </Card>
        ) : debouncedQuery && filteredResults ? (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Found {filteredResults.length} result{filteredResults.length !== 1 ? "s" : ""} for{" "}
              <span className="font-medium text-foreground">&quot;{debouncedQuery}&quot;</span>
            </p>

            {filteredResults.length === 0 ? (
              <Card>
                <CardContent className="flex flex-col items-center justify-center py-12">
                  <Search className="h-12 w-12 text-muted-foreground/30" />
                  <p className="mt-4 text-lg font-medium">No results found</p>
                  <p className="text-sm text-muted-foreground">
                    Try adjusting your search terms or filters
                  </p>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-3" ref={resultsRef}>
                {filteredResults.map((result, idx) => {
                  const Icon = typeIcons[result.type];
                  const colorClass = typeColors[result.type];
                  const isActive = activeIndex === idx;

                  return (
                    <Card
                      key={`${result.type}-${result.id}`}
                      className={cn(
                        "cursor-pointer transition-all hover:shadow-md",
                        isActive && "ring-2 ring-primary"
                      )}
                      onClick={() => handleResultClick(result)}
                    >
                      <CardContent className="flex items-start gap-4 py-4">
                        <div
                          className={cn(
                            "flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border",
                            colorClass
                          )}
                        >
                          <Icon className="h-5 w-5" />
                        </div>
                        <div className="flex-1 space-y-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="capitalize">
                              {result.type}
                            </Badge>
                            <span className="font-mono text-sm text-muted-foreground truncate">
                              {result.id}
                            </span>
                          </div>
                          <p className="font-medium">
                            <HighlightText text={result.title} query={debouncedQuery} />
                          </p>
                          <p className="text-sm text-muted-foreground line-clamp-2">
                            <HighlightText text={result.description} query={debouncedQuery} />
                          </p>
                        </div>
                        <div className="text-right shrink-0">
                          <p className="text-xs text-muted-foreground">
                            {result.timestamp
                              ? formatDistanceToNow(new Date(result.timestamp), {
                                  addSuffix: true,
                                })
                              : "—"}
                          </p>
                          <div className="mt-1 flex items-center gap-1 justify-end">
                            <div className="h-1.5 w-12 overflow-hidden rounded-full bg-muted">
                              <div
                                className="h-full bg-primary"
                                style={{ width: `${Math.max(result.relevance, 0.05) * 100}%` }}
                              />
                            </div>
                            <span className="text-xs text-muted-foreground">
                              {Math.round(result.relevance * 100)}%
                            </span>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            )}
          </div>
        ) : (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12">
              <Search className="h-12 w-12 text-muted-foreground/30" />
              <p className="mt-4 text-lg font-medium">Start searching</p>
              <p className="text-sm text-muted-foreground">
                Enter a search term to find alerts, incidents, and more
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

export default function SearchPage() {
  return (
    <Suspense fallback={<div className="p-6 space-y-4 animate-fade-in"><div className="h-7 w-32 bg-muted rounded mb-2" /><div className="h-9 w-full max-w-md bg-muted rounded" /><div className="space-y-3 mt-4">{Array.from({ length: 4 }).map((_, i) => (<div key={i} className="h-16 w-full bg-muted rounded-lg" />))}</div></div>}>
      <SearchPageInner />
    </Suspense>
  );
}
