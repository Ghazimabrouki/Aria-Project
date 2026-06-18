"use client";

import useSWR from "swr";
import { settingsAPI, type SettingsResponse } from "@/lib/api";

export function useSettings() {
  const { data, error, isLoading, mutate } = useSWR<SettingsResponse>(
    "settings-all",
    () => settingsAPI.get(),
    { revalidateOnFocus: false }
  );

  const getSectionMap = (sectionName: string): Record<string, any> => {
    if (!data) return {};
    const section = data.sections.find((s) => s.section === sectionName);
    if (!section) return {};
    return section.values.reduce((acc, item) => {
      acc[item.key] = item.value;
      return acc;
    }, {} as Record<string, any>);
  };

  return { data, error, isLoading, mutate, getSectionMap };
}
