"""
Alert Retry Queue.

Stores failed alerts in Redis for retry with exponential backoff.
"""

import asyncio
import json
import structlog
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from core.redis import get_redis_client

logger = structlog.get_logger()

RETRY_QUEUE_KEY = "opensoar:alert_retry_queue"
RETRY_PROCESSED_KEY = "opensoar:alert_retry_processed"

MAX_RETRIES = 5
BASE_DELAY = 60  # seconds


class RetryQueue:
    def __init__(self):
        self._redis = None

    async def _get_redis(self):
        if self._redis is None:
            self._redis = await get_redis_client()
        return self._redis

    async def add(self, alert: Dict[str, Any], error: str, retry_count: int = 0) -> bool:
        """Add a failed alert to the retry queue."""
        try:
            redis = await self._get_redis()
            
            entry = {
                "alert": alert,
                "error": str(error),
                "retry_count": retry_count,
                "added_at": datetime.now(timezone.utc).isoformat(),
                "next_retry_at": self._calculate_next_retry(retry_count),
            }
            
            await redis.lpush(RETRY_QUEUE_KEY, json.dumps(entry))
            logger.info("alert_retry_queued", alert_id=alert.get("id"), retry_count=retry_count)
            return True
        except Exception as e:
            logger.error("retry_queue_add_failed", error=str(e))
            return False

    def _calculate_next_retry(self, retry_count: int) -> str:
        """Calculate next retry time using exponential backoff."""
        delay = BASE_DELAY * (2 ** retry_count)
        next_time = datetime.now(timezone.utc).timestamp() + delay
        return datetime.fromtimestamp(next_time, tz=timezone.utc).isoformat()

    async def get_pending(self) -> List[Dict[str, Any]]:
        """Get all pending retries."""
        try:
            redis = await self._get_redis()
            items = await redis.lrange(RETRY_QUEUE_KEY, 0, -1)
            return [json.loads(item) for item in items]
        except Exception as e:
            logger.error("retry_queue_get_failed", error=str(e))
            return []

    async def process_queue(self, process_func) -> Dict[str, int]:
        """Process retry queue - call process_func for each alert."""
        stats = {"processed": 0, "success": 0, "failed": 0, "removed": 0}
        
        try:
            redis = await self._get_redis()
            items = await redis.lrange(RETRY_QUEUE_KEY, 0, -1)
            
            if not items:
                return stats
            
            new_queue = []
            
            for item in items:
                try:
                    entry = json.loads(item)
                    alert = entry.get("alert", {})
                    retry_count = entry.get("retry_count", 0)
                    
                    # Check if ready to retry
                    next_retry = entry.get("next_retry_at", "")
                    if next_retry:
                        next_time = datetime.fromisoformat(next_retry.replace("Z", "+00:00"))
                        now = datetime.now(timezone.utc)
                        if now < next_time:
                            # Not ready yet, keep in queue
                            new_queue.append(item)
                            continue
                    
                    # Try processing
                    try:
                        success = await process_func(alert)
                        stats["processed"] += 1
                        
                        if success:
                            stats["success"] += 1
                            stats["removed"] += 1
                            logger.info("retry_success", alert_id=alert.get("id"))
                        else:
                            # Retry failed again
                            if retry_count < MAX_RETRIES:
                                entry["retry_count"] = retry_count + 1
                                entry["next_retry_at"] = self._calculate_next_retry(retry_count + 1)
                                new_queue.append(json.dumps(entry))
                                stats["failed"] += 1
                            else:
                                stats["removed"] += 1
                                logger.warning("retry_max_retries", alert_id=alert.get("id"))
                                
                    except Exception as e:
                        logger.error("retry_process_error", alert_id=alert.get("id"), error=str(e))
                        # Keep for next attempt
                        new_queue.append(item)
                        
                except json.JSONDecodeError:
                    # Invalid entry, skip
                    stats["removed"] += 1
                    continue
            
            # Update queue with remaining items
            if new_queue:
                await redis.delete(RETRY_QUEUE_KEY)
                if new_queue:
                    await redis.rpush(RETRY_QUEUE_KEY, *new_queue)
            else:
                await redis.delete(RETRY_QUEUE_KEY)
                
        except Exception as e:
            logger.error("retry_queue_process_failed", error=str(e))
        
        return stats

    async def clear(self) -> bool:
        """Clear the retry queue."""
        try:
            redis = await self._get_redis()
            await redis.delete(RETRY_QUEUE_KEY)
            logger.info("retry_queue_cleared")
            return True
        except Exception as e:
            logger.error("retry_queue_clear_failed", error=str(e))
            return False

    async def get_stats(self) -> Dict[str, Any]:
        """Get retry queue statistics."""
        try:
            redis = await self._get_redis()
            pending = await redis.lrange(RETRY_QUEUE_KEY, 0, -1)
            
            retry_counts = {}
            for item in pending:
                try:
                    entry = json.loads(item)
                    count = entry.get("retry_count", 0)
                    retry_counts[count] = retry_counts.get(count, 0) + 1
                except:
                    pass
            
            return {
                "pending_count": len(pending),
                "by_retry_count": retry_counts,
            }
        except Exception as e:
            logger.error("retry_queue_stats_failed", error=str(e))
            return {"pending_count": 0, "by_retry_count": {}}


retry_queue = RetryQueue()