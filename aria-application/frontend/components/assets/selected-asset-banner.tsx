"use client";

import { Server, Globe } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { useSelectedAsset } from "@/lib/asset-context";

export function SelectedAssetBanner() {
  const { selectedAssetId, assets } = useSelectedAsset();
  if (!selectedAssetId) return null;

  const asset = assets.find((a) => a.asset_id === selectedAssetId);
  return (
    <Card className="border-primary/20 bg-primary/5">
      <CardContent className="flex items-center gap-3 py-3">
        <Server className="h-5 w-5 text-primary" />
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium">Selected Server:</span>
          <Badge variant="outline" className="font-mono text-xs">
            {asset?.name || selectedAssetId}
          </Badge>
          {asset?.hostname && (
            <span className="text-xs text-muted-foreground">({asset.hostname})</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export function GlobalScopeBanner() {
  const { selectedAssetId } = useSelectedAsset();
  if (selectedAssetId) return null;
  return (
    <Card className="border-muted bg-muted/30">
      <CardContent className="flex items-center gap-3 py-3">
        <Globe className="h-5 w-5 text-muted-foreground" />
        <span className="text-sm text-muted-foreground">
          Global scope — showing data from all servers
        </span>
      </CardContent>
    </Card>
  );
}
