import useSWR from "swr";
import { runtimeAPI, type RuntimeInvestigation } from "@/lib/api";

export function useRuntimeInvestigation(id: string | undefined) {
  return useSWR<RuntimeInvestigation>(
    id ? [`runtime-investigation`, id] : null,
    ([, investigationId]: [string, string]) => runtimeAPI.get(investigationId),
    { refreshInterval: 10000 }
  );
}
