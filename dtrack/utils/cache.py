"""Tiny on-disk response cache to avoid hammering remote APIs (NVD rate limits, etc.)."""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Optional


class FileCache:
    def __init__(self, cache_dir: str, ttl: int = 60 * 60 * 24) -> None:
        self.cache_dir = cache_dir
        self.ttl = ttl
        os.makedirs(cache_dir, exist_ok=True)

    def _path(self, key: str) -> str:
        h = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return os.path.join(self.cache_dir, h + ".json")

    def get(self, key: str) -> Optional[Any]:
        p = self._path(key)
        if not os.path.exists(p):
            return None
        try:
            with open(p, "r", encoding="utf-8") as f:
                rec = json.load(f)
        except Exception:  # noqa: BLE001
            return None
        if time.time() - rec.get("ts", 0) > self.ttl:
            return None
        return rec.get("data")

    def set(self, key: str, data: Any) -> None:
        p = self._path(key)
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"ts": time.time(), "data": data}, f)
        except Exception:  # noqa: BLE001
            pass

    def clear(self) -> None:
        if not os.path.isdir(self.cache_dir):
            return
        for fn in os.listdir(self.cache_dir):
            try:
                os.remove(os.path.join(self.cache_dir, fn))
            except Exception:  # noqa: BLE001
                pass
