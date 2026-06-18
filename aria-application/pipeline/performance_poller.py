"""
Performance Metrics Poller.

Polls Telegraf data from Elasticsearch and aggregates per host.
Part of the Server Performance Monitoring System (v1.0).
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

import structlog
from config import get_settings
from core.elasticsearch import search_alerts

logger = structlog.get_logger()


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


@dataclass
class HostMetrics:
    """Aggregated metrics for a single host."""
    hostname: str
    ip: Optional[str] = None
    timestamp: str = ""
    
    # CPU metrics
    cpu_usage_percent: float = 0.0
    cpu_user_percent: float = 0.0
    cpu_system_percent: float = 0.0
    cpu_iowait_percent: float = 0.0
    
    # Memory metrics
    memory_used_percent: float = 0.0
    memory_used_bytes: int = 0
    memory_available_bytes: int = 0
    
    # Disk metrics (list per device)
    disk_devices: List[Dict[str, Any]] = field(default_factory=list)
    
    # Disk directory sizes from telegraf exec (du -sh /*)
    disk_dirs: List[Dict[str, str]] = field(default_factory=list)
    
    # Network metrics
    network_bytes_recv: int = 0
    network_bytes_sent: int = 0
    
    # Process metrics (top consumers)
    top_processes: List[Dict[str, Any]] = field(default_factory=list)
    
    # Load & system
    load_1: float = 0.0
    load_5: float = 0.0
    load_15: float = 0.0
    n_cpus: int = 0
    
    # Connection stats
    tcp_established: int = 0
    tcp_listen: int = 0
    udp_socket: int = 0
    
    # Process counts
    proc_running: int = 0
    proc_sleeping: int = 0
    proc_total: int = 0
    proc_threads: int = 0
    
    # Data quality indicators
    data_fresh: bool = True
    data_stale: bool = False
    last_data_age_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)


@dataclass
class PerformancePollResult:
    """Result from a performance poll cycle."""
    hosts_processed: int = 0
    alerts_triggered: int = 0
    errors: int = 0
    duration_seconds: float = 0.0


class PerformancePoller:
    """Polls Telegraf metrics from Elasticsearch and aggregates per host."""
    
    # Data freshness thresholds
    FRESH_DATA_MAX_AGE_SECONDS = 300  # 5 minutes
    STALE_DATA_MAX_AGE_SECONDS = 600  # 10 minutes
    
    def __init__(self):
        self.settings = get_settings()
        self._cursor: Optional[datetime] = None
        self._host_metrics_cache: Dict[str, HostMetrics] = {}
        self._last_poll_time: Optional[datetime] = None
    
    def _parse_timestamp(self, doc_timestamp: str) -> Optional[datetime]:
        """Parse an Elasticsearch timestamp string to an aware datetime."""
        if not doc_timestamp or not isinstance(doc_timestamp, str):
            return None
        try:
            if 'Z' in doc_timestamp:
                return datetime.fromisoformat(doc_timestamp.replace('Z', '+00:00'))
            elif '+' in doc_timestamp or '-' in doc_timestamp[-6:]:
                return datetime.fromisoformat(doc_timestamp)
            else:
                return datetime.fromisoformat(doc_timestamp).replace(tzinfo=timezone.utc)
        except Exception:
            return None
    
    def _is_data_fresh(self, doc_timestamp: str) -> bool:
        """Check if telemetry document timestamp is fresh enough."""
        doc_time = self._parse_timestamp(doc_timestamp)
        if not doc_time:
            return False
        age_seconds = (datetime.now(timezone.utc) - doc_time).total_seconds()
        return age_seconds <= self.FRESH_DATA_MAX_AGE_SECONDS
    
    def _is_data_stale(self, doc_timestamp: str) -> bool:
        """Check if telemetry document is too old."""
        doc_time = self._parse_timestamp(doc_timestamp)
        if not doc_time:
            return True
        age_seconds = (datetime.now(timezone.utc) - doc_time).total_seconds()
        return age_seconds > self.STALE_DATA_MAX_AGE_SECONDS
    
    async def _get_cursor(self) -> datetime:
        """Get cursor for time-based polling."""
        if self._cursor is None:
            # First run: look back 5 minutes
            self._cursor = datetime.now(timezone.utc) - timedelta(minutes=5)
        return self._cursor
    
    async def _update_cursor(self, timestamp: datetime) -> None:
        """Update cursor to latest timestamp."""
        if self._cursor is None or timestamp > self._cursor:
            self._cursor = timestamp
    
    async def _get_hosts_from_telegraf(self) -> List[str]:
        """Get list of unique hosts from telegraf."""
        query = {
            "range": {
                "@timestamp": {
                    "gte": "now-1h"
                }
            }
        }
        aggregations = {
            "hosts": {
                "terms": {
                    "field": "tag.host",
                    "size": 50
                }
            }
        }
        
        try:
            response = await search_alerts(
                index_pattern=self.settings.telegraf_index_pattern,
                query=query,
                size=0,
                aggregations=aggregations
            )
            buckets = response.get("aggregations", {}).get("hosts", {}).get("buckets", [])
            hosts = [b["key"] for b in buckets]
            
            # Filter by configured hosts if specified
            if self.settings.performance_hosts_list:
                hosts = [h for h in hosts if h in self.settings.performance_hosts_list]
            
            logger.debug("performance_hosts_found", count=len(hosts), hosts=hosts)
            return hosts
        except Exception as e:
            logger.error("get_hosts_from_telegraf_failed", error=str(e))
            return []
    
    async def _get_latest_metrics_for_host(self, host: str, since: datetime) -> Optional[HostMetrics]:
        """Get latest CPU, Memory, Disk, Network metrics for a host."""
        
        # Query for CPU metrics
        cpu_query = {
            "bool": {
                "must": [
                    {"term": {"tag.host": host}},
                    {"term": {"measurement_name": "cpu"}},
                    {"term": {"tag.cpu": "cpu-total"}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}}
                ]
            }
        }
        
        # Get latest CPU
        try:
            cpu_response = await search_alerts(
                index_pattern=self.settings.telegraf_index_pattern,
                query=cpu_query,
                size=1,
                sort=[{"@timestamp": {"order": "desc"}}]
            )
        except Exception as e:
            logger.error("cpu_query_failed", host=host, error=str(e))
            return None
        
        cpu_hits = cpu_response.get("hits", {}).get("hits", [])
        if not cpu_hits:
            return None
        
        cpu_doc = cpu_hits[0].get("_source", {})
        cpu_data = cpu_doc.get("cpu", {})
        
        # Calculate CPU usage (100 - idle)
        cpu_idle = cpu_data.get("usage_idle")
        if cpu_idle is None:
            cpu_idle = 100
        cpu_usage = 100 - cpu_idle
        
        metrics = HostMetrics(
            hostname=host,
            timestamp=cpu_doc.get("@timestamp", ""),
            cpu_usage_percent=cpu_usage,
            cpu_user_percent=cpu_data.get("usage_user") or 0,
            cpu_system_percent=cpu_data.get("usage_system") or 0,
            cpu_iowait_percent=cpu_data.get("usage_iowait") or 0
        )
        
        # Validate data freshness
        doc_timestamp = cpu_doc.get("@timestamp", "")
        if doc_timestamp:
            metrics.data_fresh = self._is_data_fresh(doc_timestamp)
            metrics.data_stale = self._is_data_stale(doc_timestamp)
            
            # Calculate age
            doc_time = self._parse_timestamp(doc_timestamp)
            if doc_time:
                metrics.last_data_age_seconds = (datetime.now(timezone.utc) - doc_time).total_seconds()
            else:
                metrics.data_fresh = False
                metrics.data_stale = True
        
        # Skip stale data hosts
        if metrics.data_stale:
            logger.warning("host_data_stale", host=host, age_seconds=metrics.last_data_age_seconds)
            return None
        
        # Get Memory
        mem_query = {
            "bool": {
                "must": [
                    {"term": {"tag.host": host}},
                    {"term": {"measurement_name": "mem"}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}}
                ]
            }
        }
        
        try:
            mem_response = await search_alerts(
                index_pattern=self.settings.telegraf_index_pattern,
                query=mem_query,
                size=1,
                sort=[{"@timestamp": {"order": "desc"}}]
            )
            mem_hits = mem_response.get("hits", {}).get("hits", [])
            if mem_hits:
                mem_doc = mem_hits[0].get("_source", {})
                mem_data = mem_doc.get("mem", {})
                metrics.memory_used_percent = mem_data.get("used_percent") or 0
                metrics.memory_used_bytes = mem_data.get("used") or 0
                metrics.memory_available_bytes = mem_data.get("available") or 0
        except Exception as e:
            logger.warning("mem_query_failed", host=host, error=str(e))
        
        # Get Disk
        disk_query = {
            "bool": {
                "must": [
                    {"term": {"tag.host": host}},
                    {"term": {"measurement_name": "disk"}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}}
                ]
            }
        }
        
        try:
            disk_response = await search_alerts(
                index_pattern=self.settings.telegraf_index_pattern,
                query=disk_query,
                size=10,
                sort=[{"@timestamp": {"order": "desc"}}]
            )
            disk_hits = disk_response.get("hits", {}).get("hits", [])
            seen_disks: set = set()
            for hit in disk_hits:
                disk_doc = hit.get("_source", {})
                disk_data = disk_doc.get("disk", {})
                tag_data = disk_doc.get("tag", {})
                
                # Device info is in tag, not in disk object
                device = tag_data.get("device", "unknown")
                path = tag_data.get("path", "")
                fstype = tag_data.get("fstype", "")
                
                disk_key = (device, path)
                if disk_key in seen_disks:
                    continue
                seen_disks.add(disk_key)
                
                metrics.disk_devices.append({
                    "device": device,
                    "path": path,
                    "fstype": fstype,
                    "used_percent": disk_data.get("used_percent") or 0,
                    "used_bytes": disk_data.get("used") or 0,
                    "free_bytes": disk_data.get("free") or 0,
                    "inodes_used_percent": disk_data.get("inodes_used_percent") or 0
                })
        except Exception as e:
            logger.warning("disk_query_failed", host=host, error=str(e))
        
        # Get Network
        net_query = {
            "bool": {
                "must": [
                    {"term": {"tag.host": host}},
                    {"term": {"measurement_name": "net"}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}}
                ]
            }
        }
        
        try:
            net_response = await search_alerts(
                index_pattern=self.settings.telegraf_index_pattern,
                query=net_query,
                size=1,
                sort=[{"@timestamp": {"order": "desc"}}]
            )
            net_hits = net_response.get("hits", {}).get("hits", [])
            if net_hits:
                net_doc = net_hits[0].get("_source", {})
                net_data = net_doc.get("net", {})
                metrics.network_bytes_recv = net_data.get("bytes_recv") or 0
                metrics.network_bytes_sent = net_data.get("bytes_sent") or 0
        except Exception as e:
            logger.warning("net_query_failed", host=host, error=str(e))
        
        # Get top processes
        proc_query = {
            "bool": {
                "must": [
                    {"term": {"tag.host": host}},
                    {"term": {"measurement_name": "processes"}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}}
                ]
            }
        }
        
        try:
            proc_response = await search_alerts(
                index_pattern=self.settings.telegraf_index_pattern,
                query=proc_query,
                size=1,
                sort=[{"@timestamp": {"order": "desc"}}]
            )
            proc_hits = proc_response.get("hits", {}).get("hits", [])
            if proc_hits:
                proc_doc = proc_hits[0].get("_source", {})
                proc_data = proc_doc.get("processes", {})
                # Do NOT overwrite top_processes with aggregate state counts.
                # top_processes should only contain per-process details from procstat.
                metrics.proc_running = proc_data.get("running") or 0
                metrics.proc_sleeping = proc_data.get("sleeping") or 0
                metrics.proc_total = proc_data.get("total") or 0
                metrics.proc_threads = proc_data.get("total_threads") or 0
        except Exception as e:
            logger.warning("proc_query_failed", host=host, error=str(e))
        
        # Get system metrics (load average)
        system_query = {
            "bool": {
                "must": [
                    {"term": {"tag.host": host}},
                    {"term": {"measurement_name": "system"}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}}
                ]
            }
        }
        
        try:
            system_response = await search_alerts(
                index_pattern=self.settings.telegraf_index_pattern,
                query=system_query,
                size=1,
                sort=[{"@timestamp": {"order": "desc"}}]
            )
            system_hits = system_response.get("hits", {}).get("hits", [])
            if system_hits:
                system_doc = system_hits[0].get("_source", {})
                system_data = system_doc.get("system", {})
                metrics.load_1 = system_data.get("load1") or 0.0
                metrics.load_5 = system_data.get("load5") or 0.0
                metrics.load_15 = system_data.get("load15") or 0.0
                metrics.n_cpus = system_data.get("n_cpus") or 0
        except Exception as e:
            logger.warning("system_query_failed", host=host, error=str(e))
        
        # Get netstat metrics (connections)
        netstat_query = {
            "bool": {
                "must": [
                    {"term": {"tag.host": host}},
                    {"term": {"measurement_name": "netstat"}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}}
                ]
            }
        }
        
        try:
            netstat_response = await search_alerts(
                index_pattern=self.settings.telegraf_index_pattern,
                query=netstat_query,
                size=1,
                sort=[{"@timestamp": {"order": "desc"}}]
            )
            netstat_hits = netstat_response.get("hits", {}).get("hits", [])
            if netstat_hits:
                netstat_doc = netstat_hits[0].get("_source", {})
                netstat_data = netstat_doc.get("netstat", {})
                metrics.tcp_established = netstat_data.get("tcp_established") or 0
                metrics.tcp_listen = netstat_data.get("tcp_listen") or 0
                metrics.udp_socket = netstat_data.get("udp_socket") or 0
        except Exception as e:
            logger.warning("netstat_query_failed", host=host, error=str(e))
        
        # Get per-process CPU/memory (procstat)
        procstat_query = {
            "bool": {
                "must": [
                    {"term": {"tag.host": host}},
                    {"term": {"measurement_name": "procstat"}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}}
                ]
            }
        }
        
        try:
            procstat_response = await search_alerts(
                index_pattern=self.settings.telegraf_index_pattern,
                query=procstat_query,
                size=3000,  # Cover all processes on busy hosts (kernel threads + user-space)
                sort=[{"@timestamp": {"order": "desc"}}]
            )
            procstat_hits = procstat_response.get("hits", {}).get("hits", [])
            if procstat_hits:
                top_procs = []
                seen_pids = set()
                skipped_kernel = 0
                skipped_dup = 0
                for hit in procstat_hits:
                    proc_doc = hit.get("_source", {})
                    proc_data = proc_doc.get("procstat", {})
                    proc_tag = proc_doc.get("tag", {})
                    pid = proc_tag.get("pid") or proc_data.get("pid")
                    cpu_usage = proc_data.get("cpu_usage", 0)
                    memory_rss = proc_data.get("memory_rss", 0)
                    cmdline = proc_data.get("cmdline", "")
                    name = proc_tag.get("process_name") or "unknown"
                    
                    # Skip kernel threads (no cmdline) to keep the list actionable
                    if not cmdline:
                        skipped_kernel += 1
                        continue
                    
                    # Deduplicate by PID — keep only the most recent (hits are sorted by time desc)
                    if pid in seen_pids:
                        skipped_dup += 1
                        continue
                    seen_pids.add(pid)
                    
                    top_procs.append({
                        "name": name,
                        "pid": pid or "",
                        "cpu_percent": cpu_usage or 0,
                        "memory_rss": memory_rss or 0,
                        "num_threads": proc_data.get("num_threads") or 0
                    })
                # Sort by CPU usage descending, then by memory
                if top_procs:
                    top_procs.sort(key=lambda x: (x.get("cpu_percent", 0), x.get("memory_rss", 0)), reverse=True)
                    metrics.top_processes = top_procs[:15]
                logger.debug("procstat_processed", host=host, hits=len(procstat_hits), kept=len(top_procs), skipped_kernel=skipped_kernel, skipped_dup=skipped_dup)
        except Exception as e:
            logger.warning("procstat_query_failed", host=host, error=str(e))
        
        # Get disk directory sizes from telegraf exec (disk_dir)
        disk_dir_query = {
            "bool": {
                "must": [
                    {"term": {"tag.host": host}},
                    {"term": {"measurement_name": "disk_dir"}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}}
                ]
            }
        }
        
        try:
            disk_dir_response = await search_alerts(
                index_pattern=self.settings.telegraf_index_pattern,
                query=disk_dir_query,
                size=50,
                sort=[{"@timestamp": {"order": "desc"}}]
            )
            disk_dir_hits = disk_dir_response.get("hits", {}).get("hits", [])
            if disk_dir_hits:
                seen_paths = set()
                dirs = []
                for hit in disk_dir_hits:
                    doc = hit.get("_source", {})
                    tag = doc.get("tag", {})
                    path = tag.get("path")
                    # Try multiple possible field layouts
                    size = None
                    for key in ["disk_dir", "fields"]:
                        data = doc.get(key, {})
                        if data and "size" in data:
                            size = data.get("size")
                            break
                    if size is None:
                        # Fallback: look for "size" in doc root
                        size = doc.get("size")
                    if path and size is not None and path not in seen_paths:
                        seen_paths.add(path)
                        dirs.append({"path": path, "size_human": str(size)})
                if dirs:
                    # Sort descending by rough byte size
                    dirs.sort(key=lambda x: _parse_du_size(x["size_human"]), reverse=True)
                    metrics.disk_dirs = dirs[:20]
        except Exception as e:
            logger.warning("disk_dir_query_failed", host=host, error=str(e))
        
        return metrics
    
    async def poll_once(self) -> Dict[str, HostMetrics]:
        """Poll telegraf for current metrics - returns dict of host -> metrics."""
        
        start_time = datetime.now(timezone.utc)
        cursor = await self._get_cursor()
        
        logger.info("performance_poll_start", cursor=cursor.isoformat())
        
        # Get all hosts from telegraf
        hosts = await self._get_hosts_from_telegraf()
        
        if not hosts:
            logger.warning("performance_no_hosts_found")
            return {}
        
        # Poll metrics for each host in parallel
        tasks = [
            self._get_latest_metrics_for_host(host, cursor)
            for host in hosts
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Build metrics dict
        metrics_dict: Dict[str, HostMetrics] = {}
        
        for i, result in enumerate(results):
            host = hosts[i]
            if isinstance(result, Exception):
                logger.error("host_metrics_failed", host=host, error=str(result))
                continue
            if result:
                metrics_dict[host] = result
                ts = self._parse_timestamp(result.timestamp)
                if ts:
                    await self._update_cursor(ts)
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        logger.info(
            "performance_poll_complete",
            hosts=len(metrics_dict),
            duration_seconds=round(duration, 2)
        )
        
        # Store in cache
        self._host_metrics_cache = metrics_dict
        
        return metrics_dict
    
    def get_cached_metrics(self) -> Dict[str, HostMetrics]:
        """Get last polled metrics."""
        return self._host_metrics_cache


# Singleton instance
performance_poller = PerformancePoller()


async def run_performance_poller() -> None:
    """Main function to run performance polling loop."""
    settings = get_settings()
    
    if not settings.performance_enabled:
        logger.info("performance_poller_disabled")
        return
    
    logger.info(
        "performance_poller_starting",
        interval=settings.performance_poll_interval,
        hosts=settings.performance_hosts_list or "all"
    )
    
    while True:
        try:
            await performance_poller.poll_once()
        except Exception as e:
            logger.error("performance_poller_error", error=str(e))
        
        await asyncio.sleep(settings.performance_poll_interval)


async def get_performance_metrics() -> Dict[str, HostMetrics]:
    """Helper function to get current performance metrics."""
    return performance_poller.get_cached_metrics()