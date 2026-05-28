import redis
import os
import json
from datetime import datetime

# Initialize Redis client. Celery uses DB 0, we can use DB 1 for logs or just a specific key pattern.
# For simplicity, we'll use DB 0 but with namespaced keys.
REDIS_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")

# Lazy initialization so it doesn't break if Redis is unavailable during import
_redis_client = None

def get_redis_client():
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(REDIS_URL)
    return _redis_client

def log_scan_event(scan_job_id: str, message: str):
    """
    Appends a log message to a Redis list for a specific scan job.
    """
    if not scan_job_id:
        return
        
    client = get_redis_client()
    key = f"scan_logs:{scan_job_id}"
    
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    log_entry = json.dumps({
        "timestamp": timestamp,
        "message": message
    })
    
    try:
        client.rpush(key, log_entry)
        # Set expiration to 7 days to avoid memory leaks
        client.expire(key, 7 * 24 * 3600)
    except Exception as e:
        print(f"Failed to push log to Redis: {e}")

def get_scan_logs(scan_job_id: str):
    """
    Retrieves all log messages for a specific scan job.
    """
    if not scan_job_id:
        return []
        
    client = get_redis_client()
    key = f"scan_logs:{scan_job_id}"
    
    try:
        raw_logs = client.lrange(key, 0, -1)
        return [json.loads(r.decode('utf-8')) for r in raw_logs]
    except Exception as e:
        print(f"Failed to fetch logs from Redis: {e}")
        return []
