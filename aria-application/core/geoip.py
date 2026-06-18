"""
GeoIP resolution for IP addresses.
Uses MaxMind GeoLite2-City.mmdb with API fallback.

Phase 1: Disk-persisted cache survives restarts.
Phase 2: Async batch resolution resolves many IPs in parallel.
"""

import asyncio
import json
import math
import os
import ipaddress
from collections import OrderedDict
from pathlib import Path
from typing import Optional, Dict, List

import aiohttp
import requests
import structlog

logger = structlog.get_logger()

MMDB_PATHS = [
    "/opt/geoip/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
]

_CACHE_DIR = Path("data/artifacts/geoip_cache")
_CACHE_FILE = _CACHE_DIR / "geoip_cache.json"
_MAX_IP_CACHE_SIZE = 5000
_ip_cache: OrderedDict[str, Optional[Dict]] = OrderedDict()


def _trim_cache():
    """Evict oldest entries if cache exceeds max size."""
    excess = len(_ip_cache) - _MAX_IP_CACHE_SIZE
    if excess > 0:
        # Remove oldest 20% over the limit to avoid trimming on every insert
        to_remove = max(excess, len(_ip_cache) // 5)
        for _ in range(to_remove):
            _ip_cache.popitem(last=False)


def _load_cache():
    """Load persisted geoip cache from disk on startup."""
    global _ip_cache
    try:
        if _CACHE_FILE.exists():
            with open(_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            import time
            now = time.time()
            max_age = 7 * 86400
            loaded: OrderedDict[str, Optional[Dict]] = OrderedDict()
            for ip, entry in data.items():
                if isinstance(entry, dict):
                    if now - entry.get("_ts", 0) < max_age:
                        # Check for None-marker wrapper written by _save_cache
                        if entry.get("_null") is True:
                            loaded[ip] = None
                        else:
                            clean = {k: v for k, v in entry.items() if not k.startswith("_")}
                            loaded[ip] = clean
                elif entry is None:
                    # Legacy raw None entry
                    loaded[ip] = None
            _ip_cache = loaded
            logger.info("geoip_cache_loaded", entries=len(_ip_cache), file=str(_CACHE_FILE))
    except Exception as e:
        logger.warning("geoip_cache_load_failed", error=str(e))


def _save_cache():
    """Persist current geoip cache to disk, dropping stale entries."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        import time
        now = time.time()
        max_age = 7 * 86400
        serializable: Dict[str, Optional[Dict]] = {}
        for ip, entry in _ip_cache.items():
            if entry is None:
                # Store None with a timestamp so it can TTL on load
                serializable[ip] = {"_null": True, "_ts": now}
            else:
                ts = entry.get("_ts", now)
                if now - ts < max_age:
                    serializable[ip] = {**entry, "_ts": ts}
                # else: stale, skip
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(serializable, f, ensure_ascii=False, default=str)
    except Exception as e:
        logger.debug("geoip_cache_save_failed", error=str(e))


# Load cache on module import
_load_cache()


def _find_mmdb() -> Optional[str]:
    for p in MMDB_PATHS:
        if os.path.isfile(p):
            return p
    return None


def _is_valid_coords(lat, lon) -> bool:
    """STRICT validation: reject 0,0 defaults, out-of-bounds, null, NaN."""
    if lat is None or lon is None:
        return False
    try:
        lat = float(lat)
        lon = float(lon)
    except (TypeError, ValueError):
        return False
    if math.isnan(lat) or math.isnan(lon):
        return False
    if not (-90.0 <= lat <= 90.0):
        return False
    if not (-180.0 <= lon <= 180.0):
        return False
    if lat == 0.0 and lon == 0.0:
        return False
    return True


def _parse_geoip2_city(response) -> Optional[Dict]:
    """Extract location dict from a geoip2 City response."""
    lat = getattr(response.location, "latitude", None)
    lon = getattr(response.location, "longitude", None)
    if not _is_valid_coords(lat, lon):
        return None

    country_code = ""
    country_name = ""
    city = ""
    region = ""
    try:
        country_code = response.country.iso_code or ""
    except Exception:
        pass
    try:
        country_name = response.country.name or ""
    except Exception:
        pass
    try:
        city = response.city.name or ""
    except Exception:
        pass
    try:
        region = response.subdivisions.most_specific.name or ""
    except Exception:
        pass

    return {
        "ip": getattr(response, "traits", None) and getattr(response.traits, "ip_address", "") or "",
        "country_code": country_code,
        "country_name": country_name,
        "region": region,
        "city": city,
        "isp": "",
        "asn": "",
        "latitude": float(lat),
        "longitude": float(lon),
        "type": "mmdb",
    }


def _resolve_from_mmdb(ip: str) -> Optional[Dict]:
    mmdb = _find_mmdb()
    if not mmdb:
        return None
    try:
        import geoip2.database
        with geoip2.database.Reader(mmdb) as reader:
            resp = reader.city(ip)
            return _parse_geoip2_city(resp)
    except Exception as e:
        logger.debug("geoip_mmdb_failed", ip=ip, error=str(e))
    return None


def _resolve_from_mmdb_with_reader(ip: str, reader) -> Optional[Dict]:
    """Resolve IP using an already-open MMDB reader."""
    try:
        resp = reader.city(ip)
        return _parse_geoip2_city(resp)
    except Exception as e:
        logger.debug("geoip_mmdb_failed", ip=ip, error=str(e))
    return None


# ── Synchronous API fallback (kept for backward compat) ─────────────────────

def _resolve_from_api(ip: str) -> Optional[Dict]:
    """Fallback to free API lookups: ipapi.co then ip-api.com."""
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if r.status_code == 200:
            data = r.json()
            lat = data.get("latitude")
            lon = data.get("longitude")
            if _is_valid_coords(lat, lon):
                return {
                    "ip": ip,
                    "country_code": data.get("country_code", ""),
                    "country_name": data.get("country_name", ""),
                    "region": data.get("region", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("org", ""),
                    "asn": str(data.get("asn", "")) if data.get("asn") is not None else "",
                    "latitude": float(lat),
                    "longitude": float(lon),
                    "type": "api",
                }
    except Exception as e:
        logger.debug("geoip_api_ipapi_failed", ip=ip, error=str(e))

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                lat = data.get("lat")
                lon = data.get("lon")
                if _is_valid_coords(lat, lon):
                    return {
                        "ip": ip,
                        "country_code": data.get("countryCode", ""),
                        "country_name": data.get("country", ""),
                        "region": data.get("regionName", ""),
                        "city": data.get("city", ""),
                        "isp": data.get("isp", ""),
                        "asn": str(data.get("as", "")) if data.get("as") is not None else "",
                        "latitude": float(lat),
                        "longitude": float(lon),
                        "type": "api",
                    }
    except Exception as e:
        logger.debug("geoip_api_ipapi2_failed", ip=ip, error=str(e))

    return None


# ── Async API fallback (for batch parallel resolution) ──────────────────────

async def _resolve_from_api_async(session: aiohttp.ClientSession, ip: str) -> Optional[Dict]:
    """Async fallback to free API lookups."""
    try:
        async with session.get(f"https://ipapi.co/{ip}/json/", timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                data = await resp.json()
                lat = data.get("latitude")
                lon = data.get("longitude")
                if _is_valid_coords(lat, lon):
                    return {
                        "ip": ip,
                        "country_code": data.get("country_code", ""),
                        "country_name": data.get("country_name", ""),
                        "region": data.get("region", ""),
                        "city": data.get("city", ""),
                        "isp": data.get("org", ""),
                        "asn": str(data.get("asn", "")) if data.get("asn") is not None else "",
                        "latitude": float(lat),
                        "longitude": float(lon),
                        "type": "api",
                    }
    except Exception as e:
        logger.debug("geoip_api_async_ipapi_failed", ip=ip, error=str(e))

    try:
        async with session.get(f"http://ip-api.com/json/{ip}", timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("status") == "success":
                    lat = data.get("lat")
                    lon = data.get("lon")
                    if _is_valid_coords(lat, lon):
                        return {
                            "ip": ip,
                            "country_code": data.get("countryCode", ""),
                            "country_name": data.get("country", ""),
                            "region": data.get("regionName", ""),
                            "city": data.get("city", ""),
                            "isp": data.get("isp", ""),
                            "asn": str(data.get("as", "")) if data.get("as") is not None else "",
                            "latitude": float(lat),
                            "longitude": float(lon),
                            "type": "api",
                        }
    except Exception as e:
        logger.debug("geoip_api_async_ipapi2_failed", ip=ip, error=str(e))

    return None


def _has_city_data(result: Optional[Dict]) -> bool:
    """Check if a geo result has city-level accuracy."""
    if not result:
        return False
    return bool(result.get("city") or result.get("region"))


# ── Synchronous single-IP resolution (backward compat) ──────────────────────

def resolve_ip(ip: str) -> Optional[Dict]:
    """
    Resolve IP to location dict with valid coordinates.
    Returns None if the IP cannot be resolved to a real location.
    Private IPs return None.
    """
    if not ip:
        return None

    if ip in _ip_cache:
        _ip_cache.move_to_end(ip)
        return _ip_cache[ip]

    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            _ip_cache[ip] = None
            _trim_cache()
            return None
    except Exception:
        _ip_cache[ip] = None
        _trim_cache()
        return None

    result = _resolve_from_mmdb(ip)
    if not _has_city_data(result):
        api_result = _resolve_from_api(ip)
        if api_result:
            result = api_result

    _ip_cache[ip] = result
    _trim_cache()
    return result


# ── Async single-IP resolution (non-blocking) ───────────────────────────────

async def async_resolve_ip(ip: str) -> Optional[Dict]:
    """Async version of resolve_ip. Uses aiohttp for API fallback instead of sync requests."""
    if not ip:
        return None

    if ip in _ip_cache:
        _ip_cache.move_to_end(ip)
        return _ip_cache[ip]

    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            _ip_cache[ip] = None
            _trim_cache()
            return None
    except Exception:
        _ip_cache[ip] = None
        _trim_cache()
        return None

    result = _resolve_from_mmdb(ip)
    if not _has_city_data(result):
        try:
            async with aiohttp.ClientSession() as session:
                api_result = await _resolve_from_api_async(session, ip)
                if api_result:
                    result = api_result
        except Exception as e:
            logger.debug("async_resolve_ip_api_failed", ip=ip, error=str(e))

    _ip_cache[ip] = result
    _trim_cache()
    return result


# ── Async batch resolution (Phase 2) ───────────────────────────────────────

async def async_resolve_ips(ips: List[str]) -> Dict[str, Optional[Dict]]:
    """
    Resolve many IPs in parallel.
    Returns a dict mapping IP -> geo result.
    Uses cached results where available, resolves uncached IPs via async HTTP.
    """
    if not ips:
        return {}

    # Deduplicate and filter private/empty IPs
    unique_ips = []
    seen = set()
    for ip in ips:
        if not ip or ip in seen:
            continue
        seen.add(ip)
        if ip in _ip_cache:
            continue
        try:
            if ipaddress.ip_address(ip).is_private:
                _ip_cache[ip] = None
                continue
        except Exception:
            _ip_cache[ip] = None
            continue
        unique_ips.append(ip)

    # Fast path: all cached
    if not unique_ips:
        return {ip: _ip_cache.get(ip) for ip in seen}

    # Resolve uncached IPs in parallel with semaphore to avoid overwhelming APIs
    semaphore = asyncio.Semaphore(20)
    mmdb = _find_mmdb()

    async def _resolve_one(session: aiohttp.ClientSession, reader, ip: str) -> tuple:
        async with semaphore:
            if reader is not None:
                result = _resolve_from_mmdb_with_reader(ip, reader)
            else:
                result = None
            if not _has_city_data(result):
                api_result = await _resolve_from_api_async(session, ip)
                if api_result:
                    result = api_result
            _ip_cache[ip] = result
            return ip, result

    async with aiohttp.ClientSession() as session:
        if mmdb:
            import geoip2.database
            with geoip2.database.Reader(mmdb) as reader:
                tasks = [_resolve_one(session, reader, ip) for ip in unique_ips]
                await asyncio.gather(*tasks, return_exceptions=True)
        else:
            tasks = [_resolve_one(session, None, ip) for ip in unique_ips]
            await asyncio.gather(*tasks, return_exceptions=True)

    # Persist cache after batch (offload sync disk I/O)
    await asyncio.to_thread(_save_cache)

    return {ip: _ip_cache.get(ip) for ip in seen}


def get_coordinates(ip: str) -> tuple:
    """Get (lat, lon) tuple for map. Returns (None, None) if unavailable."""
    data = resolve_ip(ip)
    if data is not None:
        lat = data.get("latitude")
        lon = data.get("longitude")
        if _is_valid_coords(lat, lon):
            return float(lat), float(lon)
    return None, None


def is_private_ip(ip: str) -> bool:
    """Check if IP is private."""
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False
