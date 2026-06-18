"use client";

import { useState, useEffect, useMemo, useRef } from "react";
import { useRouter } from "next/navigation";
import { useSelectedAsset } from "@/lib/asset-context";
import useSWR, { mutate as swrMutate } from "swr";
import { formatDistanceToNow } from "date-fns";
import {
  Globe,
  Activity,
  Server,
  Pause,
  Play,
  X,
  ChevronRight,
  AlertTriangle,
  Shield,
  Zap,
  Target,
  Check,
  AlertCircle,
} from "lucide-react";
import {
  Map as MapCanvas,
  MapArc,
  MapMarker,
  MarkerContent,
  MarkerLabel,
  MapControls,
} from "@/components/ui/mapcn-map-arc";
import type { MapRef } from "@/components/ui/mapcn-map-arc";
import {
  ipsAPI,
  type IPSMapDataResponse,
  type IPSLiveEventsResponse,
  type IPSStatisticsResponse,
  type IPSSummaryResponse,
  type IPSFiltersResponse,
  type IPSPath,
  type IPSAttack,
} from "@/lib/api";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import { AnimatedCounter } from "@/components/animated-counter";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { Skeleton } from "@/components/ui/skeleton";



const severityColors: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

const lifecycleColors: Record<string, string> = {
  active: "#ef4444",
  investigating: "#f97316",
  mitigated: "#22c55e",
  blocked: "#a855f7",
};

const countryNames: Record<string, string> = {
  CN: "China",
  RU: "Russia",
  US: "United States",
  BR: "Brazil",
  IN: "India",
  DE: "Germany",
  FR: "France",
  GB: "United Kingdom",
  JP: "Japan",
  KR: "South Korea",
};

const hasDest = (p: IPSPath) =>
  p.to.lat != null && p.to.lon != null && !Number.isNaN(p.to.lat) && !Number.isNaN(p.to.lon);

/** Deduplicate paths for arc rendering: keep one arc per unique source-dest coordinate pair.
 *  When multiple alerts share the same path, keep the highest severity and count them.
 */
function dedupArcPaths(paths: IPSPath[]): IPSPath[] {
  const groups = new Map<string, IPSPath[]>();
  for (const p of paths) {
    const key = `${p.from.lat.toFixed(4)},${p.from.lon.toFixed(4)}->${p.to.lat.toFixed(4)},${p.to.lon.toFixed(4)}`;
    const existing = groups.get(key);
    if (existing) {
      existing.push(p);
    } else {
      groups.set(key, [p]);
    }
  }

  const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

  return Array.from(groups.values()).map((group) => {
    // Pick the highest severity representative
    const rep = group.reduce((best, cur) => {
      const bestRank = severityRank[best.severity] || 0;
      const curRank = severityRank[cur.severity] || 0;
      return curRank > bestRank ? cur : best;
    });
    // Attach count for optional visual weighting
    return { ...rep, _count: group.length } as IPSPath & { _count: number };
  });
}


function LifecycleBadge({ lifecycle }: { lifecycle?: string }) {
  const state = (lifecycle || "active").toLowerCase();
  const config: Record<string, { label: string; icon: React.ElementType; classes: string }> = {
    active: { label: "Active", icon: AlertTriangle, classes: "bg-red-500/10 text-red-500 border-red-500/20" },
    investigating: { label: "Investigating", icon: AlertCircle, classes: "bg-orange-500/10 text-orange-500 border-orange-500/20" },
    mitigated: { label: "Mitigated", icon: Check, classes: "bg-green-500/10 text-green-500 border-green-500/20" },
    blocked: { label: "Blocked", icon: X, classes: "bg-purple-500/10 text-purple-500 border-purple-500/20" },
  };
  const c = config[state] || config.active;
  const Icon = c.icon;
  return (
    <Badge variant="outline" className={cn("text-xs px-1.5 py-0 h-5 gap-1 font-medium", c.classes)}>
      <Icon className="h-3 w-3" />
      {c.label}
    </Badge>
  );
}

const colorMap: Record<string, { border: string; text: string; bg: string; from: string }> = {
  critical: { border: "border-destructive/30", text: "text-destructive", bg: "bg-destructive/10", from: "from-destructive/10" },
  high: { border: "border-chart-4/30", text: "text-chart-4", bg: "bg-chart-4/10", from: "from-chart-4/10" },
  medium: { border: "border-warning/30", text: "text-warning", bg: "bg-warning/10", from: "from-warning/10" },
  low: { border: "border-success/30", text: "text-success", bg: "bg-success/10", from: "from-success/10" },
  default: { border: "border-primary/30", text: "text-primary", bg: "bg-primary/10", from: "from-primary/10" },
};

// Stats card with animated counter
function StatSummaryCard({
  value,
  label,
  color,
  icon: Icon,
}: {
  value: number;
  label: string;
  color?: string;
  icon?: React.ElementType;
}) {
  const c = colorMap[color || "default"];
  return (
    <Card
      className={cn(
        "relative overflow-hidden transition-all duration-300 hover-lift",
        c.border
      )}
    >
      <div
        className={cn(
          "absolute inset-0 opacity-10 bg-gradient-to-br",
          c.from,
          "to-transparent"
        )}
      />
      <CardContent className="pt-4 pb-4">
        <div className="flex items-center justify-between">
          <div className="flex flex-col">
            <AnimatedCounter
              value={value}
              className={cn("text-2xl font-bold", c.text)}
              duration={800}
            />
            <span className="text-xs text-muted-foreground">{label}</span>
          </div>
          {Icon && (
            <div
              className={cn(
                "h-8 w-8 rounded-lg flex items-center justify-center",
                c.bg,
                c.text
              )}
            >
              <Icon className="h-4 w-4" />
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// Track active attack animations with unique keys for continuous spawning
interface ActiveAttack {
  id: string;
  path: IPSPath;
  spawnTime: number;
}

/** Great-circle interpolation between two [lon, lat] points. */
function interpolateArc(from: [number, number], to: [number, number], t: number): [number, number] {
  const lat1 = (from[1] * Math.PI) / 180;
  const lon1 = (from[0] * Math.PI) / 180;
  const lat2 = (to[1] * Math.PI) / 180;
  const lon2 = (to[0] * Math.PI) / 180;

  const d =
    2 *
    Math.asin(
      Math.sqrt(
        Math.pow(Math.sin((lat2 - lat1) / 2), 2) +
          Math.cos(lat1) * Math.cos(lat2) * Math.pow(Math.sin((lon2 - lon1) / 2), 2)
      )
    );

  if (d === 0) return from;

  const A = Math.sin((1 - t) * d) / Math.sin(d);
  const B = Math.sin(t * d) / Math.sin(d);

  const x = A * Math.cos(lat1) * Math.cos(lon1) + B * Math.cos(lat2) * Math.cos(lon2);
  const y = A * Math.cos(lat1) * Math.sin(lon1) + B * Math.cos(lat2) * Math.sin(lon2);
  const z = A * Math.sin(lat1) + B * Math.sin(lat2);

  const lat = (Math.atan2(z, Math.sqrt(x * x + y * y)) * 180) / Math.PI;
  const lon = (Math.atan2(y, x) * 180) / Math.PI;

  return [lon, lat];
}

/** Animated particle that travels from source → destination along a great-circle arc. */
function ArcParticle({
  from,
  to,
  color,
  duration = 2500,
  onComplete,
}: {
  from: { lon: number; lat: number };
  to: { lon: number; lat: number };
  color: string;
  duration?: number;
  onComplete?: () => void;
}) {
  const [pos, setPos] = useState<[number, number]>([from.lon, from.lat]);
  const rafRef = useRef<number | null>(null);
  const startRef = useRef<number | null>(null);

  useEffect(() => {
    const fromCoords: [number, number] = [from.lon, from.lat];
    const toCoords: [number, number] = [to.lon, to.lat];

    const tick = (ts: number) => {
      if (startRef.current === null) startRef.current = ts;
      const elapsed = ts - startRef.current;
      const progress = Math.min(elapsed / duration, 1);
      // Ease-out cubic for natural deceleration
      const eased = 1 - Math.pow(1 - progress, 3);
      const [lon, lat] = interpolateArc(fromCoords, toCoords, eased);
      setPos([lon, lat]);

      if (progress < 1) {
        rafRef.current = requestAnimationFrame(tick);
      } else {
        onComplete?.();
      }
    };

    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [from.lon, from.lat, to.lon, to.lat, duration]);

  return (
    <MapMarker longitude={pos[0]} latitude={pos[1]}>
      <MarkerContent>
        <div
          className="h-2.5 w-2.5 rounded-full border border-white/80 shadow-lg"
          style={{
            backgroundColor: color,
            boxShadow: `0 0 8px 2px ${color}`,
          }}
        />
      </MarkerContent>
    </MapMarker>
  );
}

export default function IPSMapPage() {
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(10);
  const [timeRange, setTimeRange] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [countryFilter, setCountryFilter] = useState("all");
  const [protocolFilter, setProtocolFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [lifecycleFilter, setLifecycleFilter] = useState("all");
  const [newEventIds, setNewEventIds] = useState<Set<string>>(new Set());
  const [activeAttacks, setActiveAttacks] = useState<ActiveAttack[]>([]);
  const [lastStatsUpdate, setLastStatsUpdate] = useState<Date | null>(null);
  const [lastEventsUpdate, setLastEventsUpdate] = useState<Date | null>(null);
  const mapRef = useRef<MapRef>(null);
  const lastZoomedFiltersRef = useRef({ timeRange: "all", severity: "all", country: "all", lifecycle: "all", category: "all", source: "all", protocol: "all" });
  const prevEventIdsRef = useRef<Set<string>>(new Set());
  const newEventTimeoutsRef = useRef<Set<number>>(new Set());
  const activeAttackTimeoutsRef = useRef<Set<number>>(new Set());
  const router = useRouter();
  const { selectedAssetId, setSelectedAssetId, assets } = useSelectedAsset();

  // Auto-select first available asset when "All servers" is selected
  useEffect(() => {
    if (!selectedAssetId && assets.length > 0) {
      setSelectedAssetId(assets[0].asset_id);
    }
  }, [selectedAssetId, assets, setSelectedAssetId]);

  const handleEventClick = async (event: IPSAttack) => {
    try {
      const links = await ipsAPI.getEventLinks(event.event_id);
      if (links.investigation_id) {
        router.push(`/investigations/${links.investigation_id}`);
      } else if (links.incident_id) {
        router.push(`/incidents/${links.incident_id}`);
      } else if (links.alert_id) {
        router.push(`/alerts?id=${links.alert_id}`);
      }
      // If no related records found, do nothing (no navigation)
    } catch (err) {
      // Log for debugging but don't crash UI
      // eslint-disable-next-line no-console
      console.warn("Event link lookup failed:", err);
    }
  };

  const timeRangeMinutes = useMemo(() => {
    switch (timeRange) {
      case "realtime": return 15;
      case "today": return 1440;
      case "week": return 10080;
      default: return undefined;
    }
  }, [timeRange]);

  const {
    data: mapData,
    mutate: mutateMapData,
    isLoading: mapLoading,
    error: mapError,
  } = useSWR<IPSMapDataResponse>(
    ["ips-map-data", timeRange, severityFilter, countryFilter, lifecycleFilter, categoryFilter, sourceFilter, selectedAssetId],
    () =>
      ipsAPI.getMapData({
        limit: 200,
        time_range: timeRangeMinutes,
        severity: severityFilter !== "all" ? severityFilter : undefined,
        country: countryFilter !== "all" ? countryFilter : undefined,
        lifecycle: lifecycleFilter !== "all" ? lifecycleFilter : undefined,
        category: categoryFilter !== "all" ? categoryFilter : undefined,
        source: sourceFilter !== "all" ? sourceFilter : undefined,
        asset_id: selectedAssetId || undefined,
      }),
    { refreshInterval: autoRefresh ? refreshInterval * 1000 : 0 }
  );

  const {
    data: liveEvents,
    mutate: mutateLiveEvents,
    error: liveEventsError,
  } = useSWR<IPSLiveEventsResponse>(
    ["ips-live-events", timeRange, severityFilter, countryFilter, lifecycleFilter, categoryFilter, sourceFilter, selectedAssetId],
    () =>
      ipsAPI.getLiveEvents({
        limit: 200,
        time_range: timeRangeMinutes,
        severity: severityFilter !== "all" ? severityFilter : undefined,
        country: countryFilter !== "all" ? countryFilter : undefined,
        lifecycle: lifecycleFilter !== "all" ? lifecycleFilter : undefined,
        category: categoryFilter !== "all" ? categoryFilter : undefined,
        source: sourceFilter !== "all" ? sourceFilter : undefined,
        asset_id: selectedAssetId || undefined,
      }),
    { refreshInterval: autoRefresh ? refreshInterval * 1000 : 0 }
  );

  const {
    data: statistics,
    mutate: mutateStatistics,
    error: statisticsError,
  } = useSWR<IPSStatisticsResponse>(
    ["ips-statistics", timeRange, severityFilter, countryFilter, lifecycleFilter, categoryFilter, sourceFilter, selectedAssetId],
    () =>
      ipsAPI.getStatistics({
        time_range: timeRangeMinutes,
        severity: severityFilter !== "all" ? severityFilter : undefined,
        country: countryFilter !== "all" ? countryFilter : undefined,
        lifecycle: lifecycleFilter !== "all" ? lifecycleFilter : undefined,
        category: categoryFilter !== "all" ? categoryFilter : undefined,
        source: sourceFilter !== "all" ? sourceFilter : undefined,
        asset_id: selectedAssetId || undefined,
      }),
    { refreshInterval: autoRefresh ? refreshInterval * 1000 : 0 }
  );

  const {
    data: summary,
    error: summaryError,
  } = useSWR<IPSSummaryResponse>(
    ["ips-summary", timeRange, severityFilter, countryFilter, lifecycleFilter, categoryFilter, sourceFilter, selectedAssetId],
    () =>
      ipsAPI.getSummary({
        time_range: timeRangeMinutes,
        severity: severityFilter !== "all" ? severityFilter : undefined,
        country: countryFilter !== "all" ? countryFilter : undefined,
        lifecycle: lifecycleFilter !== "all" ? lifecycleFilter : undefined,
        category: categoryFilter !== "all" ? categoryFilter : undefined,
        source: sourceFilter !== "all" ? sourceFilter : undefined,
        asset_id: selectedAssetId || undefined,
      }),
    { refreshInterval: autoRefresh ? refreshInterval * 1000 : 0 }
  );

  const {
    data: filters,
    isLoading: filtersLoading,
    error: filtersError,
  } = useSWR<IPSFiltersResponse>(["ips-filters", timeRange, severityFilter, countryFilter, lifecycleFilter, categoryFilter, sourceFilter, protocolFilter, selectedAssetId], () =>
    ipsAPI.getFilters({
      time_range: timeRangeMinutes,
      severity: severityFilter !== "all" ? severityFilter : undefined,
      country: countryFilter !== "all" ? countryFilter : undefined,
      lifecycle: lifecycleFilter !== "all" ? lifecycleFilter : undefined,
      category: categoryFilter !== "all" ? categoryFilter : undefined,
      source: sourceFilter !== "all" ? sourceFilter : undefined,
      protocol: protocolFilter !== "all" ? protocolFilter : undefined,
      asset_id: selectedAssetId || undefined,
    })
  );

  const paths = useMemo(() => mapData?.paths || [], [mapData]);

  // Backend already filters by severity, country, lifecycle, category, source.
  // We trust the backend and use paths directly.
  const activePaths = useMemo(
    () => paths.filter((p) => (p.lifecycle || "active").toLowerCase() === "active"),
    [paths]
  );
  const investigatingPaths = useMemo(
    () => paths.filter((p) => (p.lifecycle || "active").toLowerCase() === "investigating"),
    [paths]
  );
  const mitigatedPaths = useMemo(
    () => paths.filter((p) => (p.lifecycle || "active").toLowerCase() === "mitigated"),
    [paths]
  );
  const blockedPaths = useMemo(
    () => paths.filter((p) => (p.lifecycle || "active").toLowerCase() === "blocked"),
    [paths]
  );

  const activePathsWithDest = useMemo(() => activePaths.filter(hasDest), [activePaths]);
  const investigatingPathsWithDest = useMemo(() => investigatingPaths.filter(hasDest), [investigatingPaths]);
  const resolvedPaths = useMemo(() => [...mitigatedPaths, ...blockedPaths], [mitigatedPaths, blockedPaths]);
  const resolvedPathsWithDest = useMemo(() => resolvedPaths.filter(hasDest), [resolvedPaths]);

  // Deduplicated arcs for rendering (one arc per unique source-dest pair)
  const activeArcs = useMemo(() => dedupArcPaths(activePathsWithDest), [activePathsWithDest]);
  const investigatingArcs = useMemo(() => dedupArcPaths(investigatingPathsWithDest), [investigatingPathsWithDest]);
  const resolvedArcs = useMemo(() => dedupArcPaths(resolvedPathsWithDest), [resolvedPathsWithDest]);

  const events = liveEvents?.events || [];
  const stats = statistics;
  const summaryData = summary;

  // Backend already filters live events by severity, country, lifecycle, category, source.
  // Only protocol is not supported by the backend live endpoint, so we filter it client-side.
  const filteredEvents = useMemo(
    () =>
      protocolFilter !== "all"
        ? events.filter((e) => e.protocol === protocolFilter)
        : events,
    [events, protocolFilter]
  );

  // Unique source markers by lifecycle (no destination filtering)
  const uniqueActiveSources = useMemo(() => {
    const seen = new Set<string>();
    return activePaths.filter((p) => {
      const key = `${p.from.lat}-${p.from.lon}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [activePaths]);

  const uniqueInvestigatingSources = useMemo(() => {
    const seen = new Set<string>();
    return investigatingPaths.filter((p) => {
      const key = `${p.from.lat}-${p.from.lon}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [investigatingPaths]);

  const uniqueResolvedSources = useMemo(() => {
    const seen = new Set<string>();
    return resolvedPaths.filter((p) => {
      const key = `${p.from.lat}-${p.from.lon}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [resolvedPaths]);

  // Unique destination markers (only paths with valid destinations)
  const uniqueActiveDests = useMemo(() => {
    const seen = new Set<string>();
    return activePathsWithDest.filter((p) => {
      const key = `${p.to.lat}-${p.to.lon}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [activePathsWithDest]);

  const uniqueInvestigatingDests = useMemo(() => {
    const seen = new Set<string>();
    return investigatingPathsWithDest.filter((p) => {
      const key = `${p.to.lat}-${p.to.lon}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [investigatingPathsWithDest]);

  const uniqueResolvedDests = useMemo(() => {
    const seen = new Set<string>();
    return resolvedPathsWithDest.filter((p) => {
      const key = `${p.to.lat}-${p.to.lon}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [resolvedPathsWithDest]);

  // Clear transient animations when time range changes to prevent stale
  // arcs from lingering.  DO NOT reset prevPathIdsRef here — if we do,
  // the path-spawning effect that runs against the old (stale) mapData
  // will treat every old path as "new" and re-spawn transient arcs.
  useEffect(() => {
    setActiveAttacks([]);
  }, [timeRange]);

  // Aggressively clear SWR cache for all IPS keys when the time range
  // changes so we never flash stale cached map data from a previous
  // visit to the same time-range bucket.
  const clearIPSCache = () => {
    swrMutate(
      (key) => Array.isArray(key) && typeof key[0] === "string" && key[0].startsWith("ips-"),
      undefined,
      { revalidate: false }
    );
  };

  useEffect(() => {
    clearIPSCache();
  }, [timeRange]);

  // Update last-update timestamps when data arrives
  useEffect(() => {
    if (statistics) setLastStatsUpdate(new Date());
  }, [statistics]);

  useEffect(() => {
    if (liveEvents) setLastEventsUpdate(new Date());
  }, [liveEvents]);

  // Track new event IDs for highlight animation
  useEffect(() => {
    if (!liveEvents?.events) return;
    const currentIds = new Set(liveEvents.events.map((e) => e.event_id));
    const newIds = new Set<string>();
    for (const id of currentIds) {
      if (!prevEventIdsRef.current.has(id)) {
        newIds.add(id);
      }
    }
    if (newIds.size > 0) {
      setNewEventIds((prev) => new Set([...prev, ...newIds]));
      const tid = window.setTimeout(() => {
        setNewEventIds((prev) => {
          const next = new Set(prev);
          for (const id of newIds) {
            next.delete(id);
          }
          return next;
        });
        newEventTimeoutsRef.current.delete(tid);
      }, 5000);
      newEventTimeoutsRef.current.add(tid);
    }
    prevEventIdsRef.current = currentIds;
    return () => {
      newEventTimeoutsRef.current.forEach((tid) => clearTimeout(tid));
      newEventTimeoutsRef.current.clear();
    };
  }, [liveEvents]);

  // Zoom to fit when filters change and map data updates
  useEffect(() => {
    const hasFilter = timeRange !== "all" || severityFilter !== "all" || countryFilter !== "all" || lifecycleFilter !== "all" || categoryFilter !== "all" || sourceFilter !== "all" || protocolFilter !== "all";
    const filtersChanged =
      lastZoomedFiltersRef.current.timeRange !== timeRange ||
      lastZoomedFiltersRef.current.severity !== severityFilter ||
      lastZoomedFiltersRef.current.country !== countryFilter ||
      lastZoomedFiltersRef.current.lifecycle !== lifecycleFilter ||
      lastZoomedFiltersRef.current.category !== categoryFilter ||
      lastZoomedFiltersRef.current.source !== sourceFilter;

    if (filtersChanged) {
      setActiveAttacks([]);
      const map = mapRef.current;
      if (hasFilter && paths.length > 0) {
        const validPaths = paths.filter(hasDest);
        const points = validPaths.length > 0
          ? validPaths.flatMap((p) => [p.from, p.to])
          : paths.map((p) => p.from);
        const lons = points.map((p) => p.lon).filter((v) => Number.isFinite(v));
        const lats = points.map((p) => p.lat).filter((v) => Number.isFinite(v));
        if (lons.length > 0 && lats.length > 0) {
          const minLon = Math.min(...lons);
          const maxLon = Math.max(...lons);
          const minLat = Math.min(...lats);
          const maxLat = Math.max(...lats);
          map?.fitBounds(
            [[minLon, minLat], [maxLon, maxLat]],
            { padding: 60, duration: 800 }
          );
        }
        lastZoomedFiltersRef.current = { timeRange, severity: severityFilter, country: countryFilter, lifecycle: lifecycleFilter, category: categoryFilter, source: sourceFilter, protocol: protocolFilter };
      } else if (!hasFilter) {
        map?.flyTo({ center: [20, 25], zoom: 1.5, duration: 800 });
        lastZoomedFiltersRef.current = { timeRange, severity: severityFilter, country: countryFilter, lifecycle: lifecycleFilter, category: categoryFilter, source: sourceFilter, protocol: protocolFilter };
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mapData]);

  // Track previously seen path IDs to detect new arrivals
  const prevPathIdsRef = useRef<Set<string>>(new Set());

  // Event-driven: spawn transient arcs only when NEW active paths arrive
  useEffect(() => {
    if (!mapData?.paths) return;

    const currentIds = new Set(mapData.paths.map((p) => p.id));
    const newPaths = mapData.paths.filter((p) => {
      const isNew = !prevPathIdsRef.current.has(p.id);
      const isActive = (p.lifecycle || "active").toLowerCase() === "active";
      return isNew && isActive && hasDest(p);
    });

    newPaths.forEach((path, index) => {
      const staggerMs = index * 250;
      const spawnTid = window.setTimeout(() => {
        const id = `transient-${path.id}-${Date.now()}-${index}`;
        setActiveAttacks((prev) => [...prev, { id, path, spawnTime: Date.now() }]);
        const removeTid = window.setTimeout(() => {
          setActiveAttacks((prev) => prev.filter((a) => a.id !== id));
          activeAttackTimeoutsRef.current.delete(removeTid);
        }, 5000);
        activeAttackTimeoutsRef.current.add(removeTid);
        activeAttackTimeoutsRef.current.delete(spawnTid);
      }, staggerMs);
      activeAttackTimeoutsRef.current.add(spawnTid);
    });

    prevPathIdsRef.current = currentIds;
    return () => {
      activeAttackTimeoutsRef.current.forEach((tid) => clearTimeout(tid));
      activeAttackTimeoutsRef.current.clear();
    };
  }, [mapData]);

  const handleRefresh = () => {
    mutateMapData();
    mutateLiveEvents();
    mutateStatistics();
  };

  const clearFilters = () => {
    clearIPSCache();
    setTimeRange("all");
    setSeverityFilter("all");
    setCountryFilter("all");
    setProtocolFilter("all");
    setCategoryFilter("all");
    setSourceFilter("all");
    setLifecycleFilter("all");
  };

  const hasFilters = timeRange !== "all" || severityFilter !== "all" || countryFilter !== "all" || protocolFilter !== "all" || categoryFilter !== "all" || sourceFilter !== "all" || lifecycleFilter !== "all";

  const pageError = mapError || liveEventsError || statisticsError || summaryError || filtersError;

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title="Real-time traffic visualization"
        description="Real-time traffic visualization"
        onRefresh={handleRefresh}
        isLoading={mapLoading}
        actions={
          <div className="flex items-center gap-2">
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-32 max-sm:w-full">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severity</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            <Select value={countryFilter} onValueChange={setCountryFilter}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Country" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Countries</SelectItem>
                {filtersLoading ? (
                  <SelectItem value="__loading__" disabled>
                    Loading...
                  </SelectItem>
                ) : filtersError ? (
                  <SelectItem value="__error__" disabled>
                    Error loading filters
                  </SelectItem>
                ) : (
                  (filters?.countries || []).map((code) => (
                    <SelectItem key={code} value={code}>
                      {countryNames[code] || code}
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
            <Select value={protocolFilter} onValueChange={setProtocolFilter}>
              <SelectTrigger className="w-28 max-sm:w-full">
                <SelectValue placeholder="Protocol" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Protocols</SelectItem>
                {filtersLoading ? (
                  <SelectItem value="__loading__" disabled>
                    Loading...
                  </SelectItem>
                ) : filtersError ? (
                  <SelectItem value="__error__" disabled>
                    Error loading filters
                  </SelectItem>
                ) : (
                  (filters?.protocols || []).map((p) => (
                    <SelectItem key={p} value={p}>
                      {p}
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
            <Select value={categoryFilter} onValueChange={setCategoryFilter}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Category" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Categories</SelectItem>
                {filtersLoading ? (
                  <SelectItem value="__loading__" disabled>
                    Loading...
                  </SelectItem>
                ) : filtersError ? (
                  <SelectItem value="__error__" disabled>
                    Error loading filters
                  </SelectItem>
                ) : (
                  (filters?.categories || []).map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
            <Select value={sourceFilter} onValueChange={setSourceFilter}>
              <SelectTrigger className="w-32 max-sm:w-full">
                <SelectValue placeholder="Source" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Sources</SelectItem>
                {filtersLoading ? (
                  <SelectItem value="__loading__" disabled>
                    Loading...
                  </SelectItem>
                ) : filtersError ? (
                  <SelectItem value="__error__" disabled>
                    Error loading filters
                  </SelectItem>
                ) : (
                  (filters?.sources || []).map((s) => (
                    <SelectItem key={s} value={s}>
                      {s.charAt(0).toUpperCase() + s.slice(1)}
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
            {hasFilters && (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                <X className="mr-1 h-4 w-4" />
                Clear
              </Button>
            )}
            <div className="h-6 w-px bg-border" />
            <Select
              value={timeRange}
              onValueChange={(v) => {
                clearIPSCache();
                setTimeRange(v);
              }}
            >
              <SelectTrigger className="w-32 max-sm:w-full">
                <SelectValue placeholder="Time Range" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="realtime">Realtime</SelectItem>
                <SelectItem value="today">Today</SelectItem>
                <SelectItem value="week">This Week</SelectItem>
                <SelectItem value="all">All Time</SelectItem>
              </SelectContent>
            </Select>
            <div className="h-6 w-px bg-border" />
            <Select value={refreshInterval.toString()} onValueChange={(v) => setRefreshInterval(parseInt(v))}>
              <SelectTrigger className="w-24 max-sm:w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="5">5s</SelectItem>
                <SelectItem value="10">10s</SelectItem>
                <SelectItem value="30">30s</SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant={autoRefresh ? "default" : "outline"}
              size="icon"
              onClick={() => setAutoRefresh(!autoRefresh)}
              className="relative"
            >
              {autoRefresh ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
              {autoRefresh && (
                <span className="absolute -top-1 -right-1 flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-success"></span>
                </span>
              )}
            </Button>
          </div>
        }
      />


      <div className="flex-1 p-6 space-y-6 overflow-auto">
        {/* Summary Cards */}
        <div className="grid gap-4 md:grid-cols-4 lg:grid-cols-7 stagger-children">
          <StatSummaryCard value={summaryData?.total ?? 0} label="Total Traffic" icon={Globe} />
          <StatSummaryCard value={summaryData?.active ?? 0} label="Active Events" icon={Activity} />
          <StatSummaryCard value={summaryData?.unique_sources ?? 0} label="Unique Sources" icon={Target} />
          <Card className="border-destructive/30 relative overflow-hidden hover-lift transition-all">
            <div className="absolute inset-0 bg-gradient-to-br from-destructive/10 to-transparent" />
            <CardContent className="pt-4 pb-4 relative">
              <div className="flex items-center justify-between">
                <div>
                  <AnimatedCounter
                    value={summaryData?.critical ?? 0}
                    className="text-2xl font-bold text-destructive"
                    duration={800}
                  />
                  <span className="text-xs text-muted-foreground">Critical</span>
                </div>
                <div className="h-8 w-8 rounded-lg bg-destructive/10 flex items-center justify-center">
                  <AlertTriangle className="h-4 w-4 text-destructive" />
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-orange-500/30 relative overflow-hidden hover-lift transition-all">
            <div className="absolute inset-0 bg-gradient-to-br from-orange-500/10 to-transparent" />
            <CardContent className="pt-4 pb-4 relative">
              <div className="flex items-center justify-between">
                <div>
                  <AnimatedCounter
                    value={summaryData?.high ?? 0}
                    className="text-2xl font-bold text-orange-500"
                    duration={800}
                  />
                  <span className="text-xs text-muted-foreground">High</span>
                </div>
                <div className="h-8 w-8 rounded-lg bg-orange-500/10 flex items-center justify-center">
                  <Zap className="h-4 w-4 text-orange-500" />
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-yellow-500/30 relative overflow-hidden hover-lift transition-all">
            <div className="absolute inset-0 bg-gradient-to-br from-yellow-500/10 to-transparent" />
            <CardContent className="pt-4 pb-4 relative">
              <div className="flex items-center justify-between">
                <div>
                  <AnimatedCounter
                    value={summaryData?.medium ?? 0}
                    className="text-2xl font-bold text-yellow-500"
                    duration={800}
                  />
                  <span className="text-xs text-muted-foreground">Medium</span>
                </div>
                <div className="h-8 w-8 rounded-lg bg-yellow-500/10 flex items-center justify-center">
                  <Shield className="h-4 w-4 text-yellow-500" />
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-blue-500/30 relative overflow-hidden hover-lift transition-all">
            <div className="absolute inset-0 bg-gradient-to-br from-blue-500/10 to-transparent" />
            <CardContent className="pt-4 pb-4 relative">
              <div className="flex items-center justify-between">
                <div>
                  <AnimatedCounter
                    value={summaryData?.low ?? 0}
                    className="text-2xl font-bold text-blue-500"
                    duration={800}
                  />
                  <span className="text-xs text-muted-foreground">Low</span>
                </div>
                <div className="h-8 w-8 rounded-lg bg-blue-500/10 flex items-center justify-center">
                  <Server className="h-4 w-4 text-blue-500" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Map and Stats */}
        <div className="grid gap-6 lg:grid-cols-3">
          {/* World Map */}
          <Card className="lg:col-span-2 relative overflow-hidden">
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base font-medium">
                <Globe className="h-4 w-4" />
                Traffic Map
                <div className="ml-auto flex items-center gap-2">
                  {autoRefresh && (
                    <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <span className="relative flex h-2 w-2">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-success"></span>
                      </span>
                      Live
                    </div>
                  )}
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-[540px] bg-[#0b1120] rounded-lg overflow-hidden relative border border-slate-800/60">
                {mapLoading ? (
                  <div className="absolute inset-0 flex flex-col gap-4 p-6 z-10">
                    <Skeleton className="h-full w-full bg-slate-800/50 rounded-lg" />
                  </div>
                ) : mapError ? (
                  <div className="absolute inset-0 flex items-center justify-center p-6 z-10">
                    <ErrorState title="Failed to load map data" error={mapError} onRetry={mutateMapData} bordered={false} />
                  </div>
                ) : !mapData || mapData.paths.length === 0 ? (
                  <div className="absolute inset-0 flex items-center justify-center p-6 z-10">
                    <EmptyState
                      icon={Globe}
                      title="No traffic data available"
                      description="No traffic data available for the selected filters."
                      bordered={false}
                    />
                  </div>
                ) : null}

                <MapCanvas
                  ref={mapRef}
                  center={[20, 25]}
                  zoom={1.5}
                  projection={{ type: "globe" }}
                >
                  {/* Investigating arcs */}
                  <MapArc
                    data={investigatingArcs.map((p) => ({
                      id: `inv-${p.id}`,
                      from: [p.from.lon, p.from.lat] as [number, number],
                      to: [p.to.lon, p.to.lat] as [number, number],
                    }))}
                    paint={{
                      "line-color": lifecycleColors.investigating,
                      "line-width": 2.5,
                      "line-opacity": 0.9,
                    }}
                    interactive={false}
                  />

                  {/* Mitigated arcs */}
                  <MapArc
                    data={resolvedArcs
                      .filter((p) => (p.lifecycle || "mitigated").toLowerCase() === "mitigated")
                      .map((p) => ({
                        id: `mit-${p.id}`,
                        from: [p.from.lon, p.from.lat] as [number, number],
                        to: [p.to.lon, p.to.lat] as [number, number],
                      }))}
                    paint={{
                      "line-color": lifecycleColors.mitigated,
                      "line-width": 2,
                      "line-opacity": 0.85,
                      "line-dasharray": [4, 2],
                    }}
                    interactive={false}
                  />

                  {/* Blocked arcs */}
                  <MapArc
                    data={resolvedArcs
                      .filter((p) => (p.lifecycle || "blocked").toLowerCase() === "blocked")
                      .map((p) => ({
                        id: `blk-${p.id}`,
                        from: [p.from.lon, p.from.lat] as [number, number],
                        to: [p.to.lon, p.to.lat] as [number, number],
                      }))}
                    paint={{
                      "line-color": lifecycleColors.blocked,
                      "line-width": 2,
                      "line-opacity": 0.85,
                      "line-dasharray": [4, 2],
                    }}
                    interactive={false}
                  />

                  {/* Active arcs by severity */}
                  {(["critical", "high", "medium", "low"] as const).map((sev) => {
                    const arcs = activeArcs.filter((p) => (p.severity || "medium") === sev);
                    if (arcs.length === 0) return null;
                    return (
                      <MapArc
                        key={`active-${sev}`}
                        data={arcs.map((p) => ({
                          id: `act-${sev}-${p.id}`,
                          from: [p.from.lon, p.from.lat] as [number, number],
                          to: [p.to.lon, p.to.lat] as [number, number],
                        }))}
                        paint={{
                          "line-color": severityColors[sev],
                          "line-width": sev === "critical" ? 3 : 2,
                          "line-opacity": 0.9,
                        }}
                        interactive={false}
                      />
                    );
                  })}

                  {/* Active source markers */}
                  {uniqueActiveSources.map((path) => (
                    <MapMarker
                      key={`src-${path.id}`}
                      longitude={path.from.lon}
                      latitude={path.from.lat}
                    >
                      <MarkerContent>
                        <div className="relative">
                          {(path.severity === "critical" || path.severity === "high") && (
                            <span
                              className="absolute inset-0 -m-2 h-5 w-5 rounded-full animate-ping opacity-40"
                              style={{ backgroundColor: severityColors[path.severity || "medium"] }}
                            />
                          )}
                          <div
                            className="h-2.5 w-2.5 rounded-full border-2 border-white shadow-md"
                            style={{ backgroundColor: severityColors[path.severity || "medium"] }}
                          />
                        </div>
                        <MarkerLabel className="bg-slate-900/90 text-white text-[9px] px-1.5 py-0.5 rounded border border-slate-700">
                          {[path.from.city, path.from.region, path.from.country].filter(Boolean).join(", ")}
                        </MarkerLabel>
                      </MarkerContent>
                    </MapMarker>
                  ))}

                  {/* Active destination markers */}
                  {uniqueActiveDests.map((path) => (
                    <MapMarker
                      key={`dst-${path.id}`}
                      longitude={path.to.lon}
                      latitude={path.to.lat}
                    >
                      <MarkerContent>
                        <div className="h-3 w-3 rounded-full border-2 border-white bg-primary shadow-md" />
                      </MarkerContent>
                    </MapMarker>
                  ))}

                  {/* Investigating source markers */}
                  {uniqueInvestigatingSources.map((path) => (
                    <MapMarker
                      key={`inv-src-${path.id}`}
                      longitude={path.from.lon}
                      latitude={path.from.lat}
                    >
                      <MarkerContent>
                        <div className="relative">
                          <div
                            className="h-2.5 w-2.5 rounded-full border-2 border-white shadow-md"
                            style={{ backgroundColor: lifecycleColors.investigating }}
                          />
                        </div>
                      </MarkerContent>
                    </MapMarker>
                  ))}

                  {/* Investigating destination markers */}
                  {uniqueInvestigatingDests.map((path) => (
                    <MapMarker
                      key={`inv-dst-${path.id}`}
                      longitude={path.to.lon}
                      latitude={path.to.lat}
                    >
                      <MarkerContent>
                        <div className="h-3 w-3 rounded-full border-2 border-white bg-primary shadow-md" />
                      </MarkerContent>
                    </MapMarker>
                  ))}

                  {/* Resolved source markers */}
                  {uniqueResolvedSources.map((path) => (
                    <MapMarker
                      key={`res-src-${path.id}`}
                      longitude={path.from.lon}
                      latitude={path.from.lat}
                    >
                      <MarkerContent>
                        <div className="relative">
                          <div
                            className="h-2.5 w-2.5 rounded-full border-2 border-white shadow-md"
                            style={{ backgroundColor: severityColors[path.severity || "medium"] }}
                          />
                        </div>
                        <MarkerLabel className="bg-slate-900/90 text-white text-[9px] px-1.5 py-0.5 rounded border border-slate-700">
                          {(path.lifecycle || "mitigated").toLowerCase() === "mitigated" ? "✓" : "✕"}
                        </MarkerLabel>
                      </MarkerContent>
                    </MapMarker>
                  ))}

                  {/* Resolved destination markers */}
                  {uniqueResolvedDests.map((path) => (
                    <MapMarker
                      key={`res-dst-${path.id}`}
                      longitude={path.to.lon}
                      latitude={path.to.lat}
                    >
                      <MarkerContent>
                        <div className="h-3 w-3 rounded-full border-2 border-white bg-primary shadow-md" />
                      </MarkerContent>
                    </MapMarker>
                  ))}

                  {/* Transient active attack traveling particles */}
                  {activeAttacks.map((attack) => (
                    <ArcParticle
                      key={attack.id}
                      from={{ lon: attack.path.from.lon, lat: attack.path.from.lat }}
                      to={{ lon: attack.path.to.lon, lat: attack.path.to.lat }}
                      color={severityColors[attack.path.severity || "medium"]}
                      duration={2500}
                      onComplete={() => {
                        setActiveAttacks((prev) => prev.filter((a) => a.id !== attack.id));
                      }}
                    />
                  ))}

                  <MapControls showZoom position="top-right" />
                </MapCanvas>
              </div>

              {/* Legends */}
              <div className="mt-4 pt-4 border-t border-border/50 space-y-3">
                {/* Lifecycle legend with counts */}
                <div className="flex items-center justify-center gap-3 flex-wrap">
                  {[
                    { key: "active", label: "Active", color: "#ef4444" },
                    { key: "investigating", label: "Investigating", color: "#f97316" },
                    { key: "mitigated", label: "Mitigated", color: "#22c55e" },
                    { key: "blocked", label: "Blocked", color: "#a855f7" },
                  ].map(({ key, label, color }) => {
                    const count = stats?.by_lifecycle?.find((l) => l.lifecycle === key)?.count ?? 0;
                    const isActive = lifecycleFilter === key;
                    return (
                      <button
                        key={key}
                        onClick={() => setLifecycleFilter(isActive ? "all" : key)}
                        className={cn(
                          "flex items-center gap-2 px-2.5 py-1 rounded-full border transition-all",
                          isActive
                            ? "bg-background shadow-sm"
                            : "bg-transparent border-transparent hover:border-border"
                        )}
                        style={isActive ? { borderColor: color } : undefined}
                        title={`Filter by ${label}`}
                      >
                        <div
                          className="w-3 h-3 rounded-full"
                          style={{ backgroundColor: color, boxShadow: `0 0 8px ${color}40` }}
                        />
                        <span className={cn("text-xs", isActive ? "text-foreground font-medium" : "text-muted-foreground")}>
                          {label}
                        </span>
                        <span
                          className="text-xs px-1.5 py-0 rounded-full font-medium"
                          style={{ backgroundColor: `${color}20`, color }}
                        >
                          {count}
                        </span>
                      </button>
                    );
                  })}
                  {lifecycleFilter !== "all" && (
                    <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={() => setLifecycleFilter("all")}>
                      <X className="mr-1 h-3 w-3" />
                      Clear
                    </Button>
                  )}
                </div>

                {/* Severity legend with counts */}
                <div className="flex items-center justify-center gap-3 flex-wrap">
                  {[
                    { key: "critical", label: "Critical", color: "#ef4444" },
                    { key: "high", label: "High", color: "#f97316" },
                    { key: "medium", label: "Medium", color: "#eab308" },
                    { key: "low", label: "Low", color: "#3b82f6" },
                  ].map(({ key, label, color }) => {
                    const count = stats?.by_severity?.[key] ?? 0;
                    const isActive = severityFilter === key;
                    return (
                      <button
                        key={key}
                        onClick={() => setSeverityFilter(isActive ? "all" : key)}
                        className={cn(
                          "flex items-center gap-2 px-2.5 py-1 rounded-full border transition-all",
                          isActive
                            ? "bg-background shadow-sm"
                            : "bg-transparent border-transparent hover:border-border"
                        )}
                        style={isActive ? { borderColor: color } : undefined}
                        title={`Filter by ${label}`}
                      >
                        <div
                          className="w-3 h-3 rounded-full"
                          style={{ backgroundColor: color, boxShadow: `0 0 8px ${color}40` }}
                        />
                        <span className={cn("text-xs", isActive ? "text-foreground font-medium" : "text-muted-foreground")}>
                          {label}
                        </span>
                        <span
                          className="text-xs px-1.5 py-0 rounded-full font-medium"
                          style={{ backgroundColor: `${color}20`, color }}
                        >
                          {count}
                        </span>
                      </button>
                    );
                  })}
                  {severityFilter !== "all" && (
                    <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={() => setSeverityFilter("all")}>
                      <X className="mr-1 h-3 w-3" />
                      Clear
                    </Button>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Statistics */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base font-medium">
                <Activity className="h-4 w-4" />
                Statistics
                <span className="text-xs text-muted-foreground ml-auto">
                  {lastStatsUpdate ? `Updated ${formatDistanceToNow(lastStatsUpdate, { addSuffix: true })}` : ""}
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-5">
              {statisticsError ? (
                <ErrorState title="Failed to load statistics" error={statisticsError} onRetry={mutateStatistics} bordered={false} />
              ) : !stats ? (
                <div className="text-sm text-muted-foreground">Loading statistics...</div>
              ) : (
                <>
                  {/* Top Sources */}
                  <div>
                    <p className="text-sm font-medium mb-3">Top Traffic Sources</p>
                    <div className="space-y-3">
                      {(
                        (stats.top_sources?.length ? stats.top_sources : stats.top_countries) || []
                      )
                        .slice(0, 5)
                        .map((item: any, i: number) => {
                          const percent = stats.total_attacks > 0 ? (item.count / stats.total_attacks) * 100 : 0;
                          const label = item.ip || item.name || countryNames[item.code] || item.code;
                          const key = item.ip || item.code || i;
                          return (
                            <div
                              key={key}
                              className="space-y-1.5 animate-slide-up"
                              style={{ animationDelay: `${i * 50}ms` }}
                            >
                              <div className="flex items-center justify-between text-sm">
                                <span className="flex items-center gap-2">
                                  <span className="text-muted-foreground w-4 text-xs">{i + 1}.</span>
                                  <span className="truncate max-w-[140px]" title={label}>
                                    {label}
                                  </span>
                                  {item.country && (
                                    <Badge variant="outline" className="text-xs px-1 py-0 h-4">
                                      {item.country}
                                    </Badge>
                                  )}
                                </span>
                                <span className="text-muted-foreground font-mono text-xs">
                                  {item.count.toLocaleString()}
                                </span>
                              </div>
                              <div className="relative">
                                <Progress value={percent} className="h-2" />
                              </div>
                            </div>
                          );
                        })}
                    </div>
                  </div>

                  {/* By Category */}
                  <div>
                    <p className="text-sm font-medium mb-3">Traffic Categories</p>
                    <div className="space-y-2">
                      {(stats.by_category || []).slice(0, 4).map((c, i) => (
                        <div
                          key={c.category}
                          className="flex items-center justify-between text-sm p-2 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors animate-slide-up"
                          style={{ animationDelay: `${(i + 5) * 50}ms` }}
                        >
                          <span className="truncate max-w-[160px] text-muted-foreground">{c.category}</span>
                          <Badge variant="secondary" className="font-mono">
                            {c.count}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* By Protocol */}
                  <div>
                    <p className="text-sm font-medium mb-3">Protocols</p>
                    <div className="flex gap-2 flex-wrap">
                      {(stats.by_protocol || []).map((p, i) => (
                        <Badge
                          key={p.protocol}
                          variant="outline"
                          className="cursor-pointer hover:bg-accent transition-colors animate-scale-in"
                          style={{ animationDelay: `${(i + 9) * 50}ms` }}
                          onClick={() => setProtocolFilter(p.protocol)}
                        >
                          {p.protocol}: <span className="font-mono ml-1">{p.count}</span>
                        </Badge>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Live Events Table */}
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2 text-base font-medium">
                <AlertTriangle className="h-4 w-4" />
                Live Events
                {autoRefresh && (
                  <span className="relative flex h-2 w-2 ml-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-success"></span>
                  </span>
                )}
                <span className="text-xs text-muted-foreground ml-2">
                  {lastEventsUpdate ? `Updated ${formatDistanceToNow(lastEventsUpdate, { addSuffix: true })}` : ""}
                </span>
              </CardTitle>
              <Badge variant="secondary" className="font-mono">
                {liveEvents?.total ?? filteredEvents.length} events
                {liveEvents && liveEvents.total > liveEvents.count && (
                  <span className="ml-1 text-xs opacity-70">(showing {liveEvents.count})</span>
                )}
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            {liveEventsError ? (
              <ErrorState title="Failed to load live events" error={liveEventsError} onRetry={mutateLiveEvents} bordered={false} />
            ) : !liveEvents ? (
              <div className="text-sm text-muted-foreground">Loading live events...</div>
            ) : filteredEvents.length === 0 ? (
              <div className="text-sm text-muted-foreground">
                <p>No events found for the selected filters.</p>
              </div>
            ) : (
              <ScrollArea className="h-[320px]">
                <div className="space-y-2">
                  {filteredEvents.map((event, i) => (
                    <div
                      key={event.event_id}
                      className={cn(
                        "flex items-center gap-4 p-3 rounded-lg border bg-card hover:bg-accent/50 transition-all duration-200 cursor-pointer",
                        newEventIds.has(event.event_id) && "animate-slide-in-right border-primary/50 bg-primary/5"
                      )}
                      onClick={() => handleEventClick(event as unknown as IPSAttack)}
                      style={{ animationDelay: `${i * 30}ms` }}
                    >
                      <div className="relative">
                        <div
                          className="w-3 h-3 rounded-full shrink-0"
                          style={{
                            backgroundColor: severityColors[event.severity],
                            boxShadow: `0 0 8px ${severityColors[event.severity]}60`,
                          }}
                        />
                        {(event.severity === "critical" || event.severity === "high") && (
                          <div
                            className="absolute inset-0 rounded-full animate-ping"
                            style={{ backgroundColor: severityColors[event.severity], opacity: 0.4 }}
                          />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{event.alert_name}</p>
                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                          <span className="font-mono">{event.source_ip}</span>
                          {event.source_country_code && (
                            <Badge variant="outline" className="text-xs px-1 py-0 h-4">
                              {event.source_country_code}
                            </Badge>
                          )}
                          <ChevronRight className="h-3 w-3" />
                          <span>
                            {event.source_city ? `${event.source_city}, ` : ""}
                            {event.source_country}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <Badge variant="outline" className="text-xs">
                          {event.protocol}
                        </Badge>
                        <LifecycleBadge lifecycle={event.lifecycle} />
                        <Badge variant="secondary" className="text-xs max-w-[140px] truncate" title={event.category}>
                          {event.category}
                        </Badge>
                      </div>
                      <span className="text-xs text-muted-foreground shrink-0 w-20 text-right">
                        {event.timestamp
                          ? formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })
                          : "Unknown"}
                      </span>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
