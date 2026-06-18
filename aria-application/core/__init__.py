from core.elasticsearch import get_es_client, close_es_client, search_alerts, get_latest_alerts, get_alert_by_id, count_alerts
from core.redis import get_redis_client, close_redis_client, RedisManager

__all__ = [
    "get_es_client",
    "close_es_client", 
    "search_alerts",
    "get_latest_alerts",
    "get_alert_by_id",
    "count_alerts",
    "get_redis_client",
    "close_redis_client",
    "RedisManager",
]