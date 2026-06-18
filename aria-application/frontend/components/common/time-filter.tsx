"use client";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export type TimePreset = "all" | "1h" | "2h" | "5h" | "24h" | "7d";

export function timePresetToRange(preset: TimePreset): { time_from?: string } {
  if (preset === "all") return {};
  const now = Date.now();
  let from: string;
  switch (preset) {
    case "1h":
      from = new Date(now - 1 * 60 * 60 * 1000).toISOString();
      break;
    case "2h":
      from = new Date(now - 2 * 60 * 60 * 1000).toISOString();
      break;
    case "5h":
      from = new Date(now - 5 * 60 * 60 * 1000).toISOString();
      break;
    case "24h":
      from = new Date(now - 24 * 60 * 60 * 1000).toISOString();
      break;
    case "7d":
      from = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();
      break;
    default:
      return {};
  }
  return { time_from: from };
}

interface TimeFilterProps {
  value: TimePreset;
  onChange: (preset: TimePreset) => void;
  className?: string;
}

export function TimeFilter({ value, onChange, className }: TimeFilterProps) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v as TimePreset)}>
      <SelectTrigger className={className || "w-36"}>
        <SelectValue placeholder="Time range" />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="all">All time</SelectItem>
        <SelectItem value="1h">Last 1 hour</SelectItem>
        <SelectItem value="2h">Last 2 hours</SelectItem>
        <SelectItem value="5h">Last 5 hours</SelectItem>
        <SelectItem value="24h">Last 24 hours</SelectItem>
        <SelectItem value="7d">Last 7 days</SelectItem>
      </SelectContent>
    </Select>
  );
}
