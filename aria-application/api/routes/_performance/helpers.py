"""Performance route helper functions."""
from typing import Optional, Dict, Any, List
from fastapi import HTTPException
from response.models import MonitoredAsset


def _host_matches_asset(host: str, asset: MonitoredAsset) -> bool:
    """Check if a host identifier matches an asset by hostname or IP."""
    if not host:
        return False
    if asset.hostname and host.lower() == asset.hostname.lower():
        return True
    if asset.ip_address and host == asset.ip_address:
        return True
    return False

async def _get_asset_or_404(asset_id: Optional[str]) -> Optional[MonitoredAsset]:
    """Fetch and validate a MonitoredAsset by asset_id."""
    if not asset_id or asset_id.lower() == "all":
        return None
    from response.db import AsyncSessionLocal
    from sqlalchemy import select
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
        )
        asset = result.scalar_one_or_none()
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
        if not asset.enabled:
            raise HTTPException(status_code=400, detail=f"Asset {asset_id} is disabled")
        return asset

def _parse_du_size(size_human: str) -> float:
    """Roughly parse du -sh output to bytes for sorting."""
    size_human = size_human.strip().replace(",", ".")
    multipliers = {"B": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    try:
        if size_human[-1].upper() in multipliers:
            return float(size_human[:-1]) * multipliers[size_human[-1].upper()]
        return float(size_human)
    except Exception:
        return 0.0

def _get_disk_heuristics(
    disk_devices: List[Dict[str, Any]],
    top_processes: Optional[List[Dict[str, Any]]] = None
) -> List[str]:
    """Return likely disk space consumers when exact data is unavailable."""
    heuristics = []
    procs = [p.get("name", "").lower() for p in (top_processes or [])]
    has_docker = any("docker" in pname or "containerd" in pname for pname in procs)
    has_k8s = any("kubelet" in pname or "kube-apiserver" in pname for pname in procs)
    has_java = any("java" in pname for pname in procs)
    has_db = any(pname in ("postgres", "mysql", "mariadb", "mongodb") for pname in procs)
    has_web = any(pname in ("nginx", "apache2", "httpd") for pname in procs)
    has_falco = any("falco" in pname for pname in procs)
    has_telegraf = any("telegraf" in pname for pname in procs)

    for d in disk_devices:
        path = d.get("path", "/")
        used_pct = d.get("used_percent", 0) or 0
        if path.startswith("/run/snapd/ns"):
            continue
        if path in ("/", ""):
            items = ["`/var/log` system and application logs"]
            if has_docker or has_k8s:
                items.append("`/var/lib/docker` container images and layers")
                items.append("`/var/lib/containerd` container storage")
            else:
                items.append("`/var/lib/docker` container images (if Docker installed)")
            items.append("`/tmp` and `/var/tmp` temporary files")
            items.append("package manager cache (`/var/cache/apt` or `/var/cache/yum`)")
            if has_k8s:
                items.append("`/var/lib/etcd` Kubernetes etcd data")
                items.append("`/var/lib/kubelet` pod volumes and logs")
            if has_java:
                items.append("`/opt` or `/var` Java heap dumps and application logs")
            if has_db:
                items.append("`/var/lib/postgresql` or `/var/lib/mysql` database files and WAL logs")
            if has_web:
                items.append("`/var/log/nginx` or `/var/log/apache2` access and error logs")
            if has_falco:
                items.append("`/var/log/falco` Falco security event logs")
            if has_telegraf:
                items.append("`/var/lib/telegraf` buffer and queue files")
            if used_pct > 80:
                items.append("old kernel packages and retained boot images in `/boot`")
            heuristics.append("Root partition likely contains: " + ", ".join(items))
        elif path.startswith("/home"):
            heuristics.append(f"`{path}` — user home directories, downloads, media files, development projects")
        elif path.startswith("/var"):
            heuristics.append(f"`{path}` — databases, application persistent data, rotating logs, mail spool")
        elif path.startswith("/opt"):
            heuristics.append(f"`{path}` — third-party applications, vendor binaries, large SDKs")
        else:
            heuristics.append(f"`{path}` — application data, logs, temp files, or mounted datasets")
    return heuristics

def _resolve_ansible_host(host: str) -> str:
    """Try to resolve a hostname to its ansible_host IP from the local inventory."""
    import os
    import re
    inventory_paths = [
        os.path.join(os.path.dirname(__file__), "..", "..", "config", "ansible_inventory"),
        "/etc/ansible/inventory",
        "/etc/ansible/hosts",
    ]
    for path in inventory_paths:
        path = os.path.abspath(path)
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    content = f.read()
                # Look for line like: ghazi ansible_host=193.95.30.97 ...
                match = re.search(rf"^\s*{re.escape(host)}\s+.*ansible_host\s*=\s*(\S+)", content, re.MULTILINE)
                if match:
                    return match.group(1)
            except Exception:
                continue
    return host

