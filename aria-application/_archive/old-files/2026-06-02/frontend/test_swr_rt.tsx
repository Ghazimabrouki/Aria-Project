import useSWR from "swr";
import { runtimeAPI } from "@/lib/api";

export function Test({ id }: { id: string }) {
  const { data } = useSWR(
    id ? `runtime-investigation-${id}` : null,
    () => runtimeAPI.get(id)
  );
  return <div>{(data as any)?.id}</div>;
}
