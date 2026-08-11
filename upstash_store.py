"""Minimal Upstash Redis REST client (stdlib only) for persisting game state.

On cloud deployments (e.g. Zeabur) the container filesystem may be ephemeral,
so the full `mem` dict is stored in Upstash Redis (free tier: 500K cmd/month,
no credit card) as the source of truth. Falls back to local game_data.json
when Upstash is not configured or unreachable.
"""
import os
import json
import urllib.request
import urllib.error

UP_URL = os.environ.get("UPSTASH_REDIS_REST_URL", "")
UP_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN", "")
MEM_KEY = "rollingball:mem"


def available():
    return bool(UP_URL and UP_TOKEN)


def ups_get(key):
    if not available():
        return None
    url = f"{UP_URL}/get/{key}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {UP_TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = json.loads(r.read().decode("utf-8"))
        result = body.get("result")
        if result is None:
            return None
        if isinstance(result, str):
            try:
                return json.loads(result)
            except Exception:
                return result
        return result
    except Exception as e:
        print(f"[Upstash] GET {key} failed: {e!r}")
        return None


def ups_set(key, value):
    if not available():
        return False
    # Store value as a JSON string (Upstash's JSON-string convention).
    payload = json.dumps(["SET", key, json.dumps(value, ensure_ascii=False)])
    req = urllib.request.Request(
        UP_URL,
        data=payload.encode("utf-8"),
        headers={"Authorization": f"Bearer {UP_TOKEN}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            json.loads(r.read().decode("utf-8"))
        return True
    except Exception as e:
        print(f"[Upstash] SET {key} failed: {e!r}")
        return False
