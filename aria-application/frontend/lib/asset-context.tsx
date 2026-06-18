"use client";

import { createContext, useContext, useEffect, useState, ReactNode, Suspense } from "react";
import { useSearchParams, useRouter, usePathname } from "next/navigation";
import { assetsAPI, type MonitoredAsset } from "@/lib/api";
import useSWR from "swr";

interface AssetContextValue {
  selectedAssetId: string | null;
  setSelectedAssetId: (id: string | null) => void;
  assets: MonitoredAsset[];
  isLoading: boolean;
}

const AssetContext = createContext<AssetContextValue>({
  selectedAssetId: null,
  setSelectedAssetId: () => {},
  assets: [],
  isLoading: false,
});

function AssetProviderInner({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [selectedAssetId, setSelectedAssetIdState] = useState<string | null>(
    searchParams.get("asset_id")
  );

  const { data, isLoading } = useSWR("assets-list", () => assetsAPI.list(), {
    refreshInterval: 30000,
  });
  const assets = data?.assets?.filter((a) => a.enabled) ?? [];

  const setSelectedAssetId = (id: string | null) => {
    setSelectedAssetIdState(id);
    const params = new URLSearchParams(searchParams.toString());
    if (id) {
      params.set("asset_id", id);
    } else {
      params.delete("asset_id");
    }
    router.replace(`${pathname}?${params.toString()}`);
  };

  // Sync with URL changes
  useEffect(() => {
    const urlAssetId = searchParams.get("asset_id");
    setSelectedAssetIdState(urlAssetId);
  }, [searchParams]);

  return (
    <AssetContext.Provider value={{ selectedAssetId, setSelectedAssetId, assets, isLoading }}>
      {children}
    </AssetContext.Provider>
  );
}

export function SelectedAssetProvider({ children }: { children: ReactNode }) {
  return (
    <Suspense fallback={
      <AssetContext.Provider value={{ selectedAssetId: null, setSelectedAssetId: () => {}, assets: [], isLoading: true }}>
        {children}
      </AssetContext.Provider>
    }>
      <AssetProviderInner>{children}</AssetProviderInner>
    </Suspense>
  );
}

export function useSelectedAsset() {
  return useContext(AssetContext);
}
