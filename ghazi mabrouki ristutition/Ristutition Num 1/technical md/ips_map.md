# IPS Attack Visualization — Technical Documentation

## 1. Feature name
IPS Attack Visualization (World Map)

## 2. Purpose
Merge upstream OpenSOAR alerts and local SQLite alerts into geo-enriched IPS events, render an interactive world map with animated attack paths, and display lifecycle status, statistics, and live events.

## 3. Input
- Upstream OpenSOAR alerts (when `UPSTREAM_ENABLED=true`).
- Local SQLite `Alert` rows + `Investigation` / `PlaybookApproval` / `PlaybookRun` / `FixVerification`.
- GeoIP resolution (`core/geoip.py` + `pipeline/enrichment/geoip.py`).

## 4. Processing steps
1. **Fetch** (`api/routes/ips.py`) — Query upstream alerts + local alerts + manual events.
2. **Deduplicate** — Merge by source IP + timestamp window; upstream wins on conflict.
3. **Geolocate** — `async_resolve_ip()` / `enrich_ip()` → country, city, lat, lon, ASN, provider (AWS/Azure/GCP via ASN keywords).
4. **Categorize** — `_alert_to_event()` derives category from `metadata` or title pattern matching (brute-force, web-attack, reconnaissance, malware, etc.).
5. **Lifecycle** — `_get_lifecycle_for_alert()` queries investigation chain → `blocked` > `mitigated` > `investigating` > `active`.
6. **Filter & Serve** — Apply severity/country/protocol/category/source/lifecycle/time filters; return map data, statistics, live events.

## 5. Output
- GeoJSON-like event arrays for `react-simple-maps`.
- Statistics: top countries, attack categories, severity distribution, trend counts.
- Filter metadata enums.

## 6. Main files
| File | Role |
|------|------|
| `api/routes/ips.py` | Merge, dedup, geo-enrich, lifecycle, endpoints |
| `core/geoip.py` | MaxMind + ipapi.co + ip-api.com resolver |
| `pipeline/enrichment/geoip.py` | Cloud-provider enrichment via ASN |
| `frontend/app/(dashboard)/ips/page.tsx` | World map UI (~1,906 lines) |

## 7. API endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/ips/event` | Create manual event |
| GET | `/ips/map-data` | Geo events for map rendering |
| GET | `/ips/events` | Paginated event list |
| GET | `/ips/events/live` | Recent events for ticker |
| GET | `/ips/statistics` | Aggregate stats |
| GET | `/ips/countries` | Country breakdown |
| GET | `/ips/filters` | Available filter enums |
| GET | `/ips/event/{id}/links` | Related investigations/incidents |

## 8. Database tables
- `Alert`
- `Investigation`
- `PlaybookApproval`
- `PlaybookRun`
- `FixVerification`
- `Incident`
- `AlertIncidentLink`

## 9. Background jobs
None dedicated; relies on Alert Pipeline poller + Watcher to populate data.

## 10. Frontend page
- **Route**: `/ips`
- **File**: `frontend/app/(dashboard)/ips/page.tsx`
- **Features**:
  - `react-simple-maps` with `geoMercator`
  - Animated SVG attack paths (lifecycle-based line styles)
  - Filter dropdowns, live events table, statistics sidebar
  - Auto-refresh intervals

## 11. Example
Suricata alert from `185.220.101.4` → geo-resolved to Germany → category `reconnaissance` → investigation created → playbook approved → executed → lifecycle `blocked` → map renders red attack line with `blocked` dashed style.

## 12. Known limitations
- No `frontend/components/ips/` directory; page is self-contained.
- Private RFC-1918 IPs are filtered out of map rendering.
- Strict coordinate validation rejects `(0,0)` to avoid MaxMind default-location noise.
