import { format } from "date-fns";

/**
 * Safely parse an ISO date string or Date into a Date object.
 * Returns null if invalid.
 */
export function safeParseDate(dateish: string | Date | null | undefined): Date | null {
  if (!dateish) return null;
  let s: string | Date = dateish;
  if (typeof s === "string") {
    // Backend returns UTC ISO strings without Z (e.g. "2026-05-19T11:14:46.292339").
    // JavaScript parses these as local time, which is wrong.
    // If the string looks like an ISO datetime with no timezone suffix, append Z.
    if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(s)) {
      s = s.replace(" ", "T") + "Z";
    }
  }
  const d = typeof s === "string" ? new Date(s) : s;
  if (isNaN(d.getTime())) return null;
  return d;
}

/**
 * Format a date-ish value as an absolute date/time string.
 * Returns "—" if invalid or missing.
 */
export function formatAbsoluteDateTime(
  dateish: string | Date | null | undefined
): string {
  const d = safeParseDate(dateish);
  if (!d) return "—";
  return format(d, "yyyy-MM-dd HH:mm:ss");
}

/**
 * Return the best available timestamp string for a record based on its entity type.
 * Priority order tries real event time before DB creation time.
 */
export function getEventTimestamp(
  record: Record<string, any> | null | undefined,
  type: "alert" | "incident" | "investigation" | "runtime" | "infrastructure"
): string | null {
  if (!record) return null;
  const r = record;
  switch (type) {
    case "alert":
      return (r.timestamp as string) || (r.event_time as string) || (r.created_at as string) || null;
    case "incident":
      return (r.timestamp as string) || (r.created_at as string) || null;
    case "investigation":
      return (r.created_at as string) || null;
    case "runtime":
      return (r.last_seen as string) || (r.first_seen as string) || (r.created_at as string) || null;
    case "infrastructure":
      return (r.created_at as string) || null;
    default:
      return (r.created_at as string) || null;
  }
}

/**
 * Convenience: format absolute date/time using the best timestamp for a record.
 */
export function formatRecordDateTime(
  record: Record<string, any> | null | undefined,
  type: "alert" | "incident" | "investigation" | "runtime" | "infrastructure"
): string {
  const ts = getEventTimestamp(record, type);
  return formatAbsoluteDateTime(ts);
}
