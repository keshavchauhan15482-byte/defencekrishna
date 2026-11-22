"""Validated, bounded near-live advisory feed for completed-capture sensor results."""
from __future__ import annotations

import collections
import hmac
import math
import re
import threading
import time


class LiveFeedError(ValueError):
    pass


class LiveFeed:
    HORIZONS = (10, 20, 30, 40)
    MAX_AGE = 300
    STALE_AFTER = 120

    def __init__(self, token="", clock=None):
        if not isinstance(token, str) or (
            token and (not 32 <= len(token) <= 256
                       or any(ord(c) < 33 or ord(c) > 126 for c in token))
        ):
            raise ValueError("Sensor token must be 32-256 non-whitespace ASCII characters")
        self._token = token
        self._clock = clock or time.time
        self._events = collections.deque(maxlen=128)
        self._lock = threading.Lock()
        self._last_id = 0

    @property
    def enabled(self):
        return bool(self._token)

    def authorized(self, header):
        return (self.enabled and isinstance(header, str) and
                header.startswith("Bearer ") and
                hmac.compare_digest(header[7:], self._token))

    def append(self, data):
        keys = {"schema", "kind", "capture_sha256", "model_sha256",
                "cutoff_epoch_seconds", "trajectory", "alert", "supported",
                "automatic_containment"}
        if not self.enabled:
            raise LiveFeedError("Sensor not enabled")
        if not isinstance(data, dict) or set(data) != keys:
            raise LiveFeedError("Unexpected schema fields")
        if data["schema"] != "krishna-live-v1" or data["kind"] != "forecast":
            raise LiveFeedError("Unsupported event")
        for key in ("capture_sha256", "model_sha256"):
            if not isinstance(data[key], str) or not re.fullmatch("[0-9a-fA-F]{64}", data[key]):
                raise LiveFeedError("Missing SHA-256 provenance")
        if (type(data["alert"]) is not bool or type(data["supported"]) is not bool
                or data["automatic_containment"] is not False):
            raise LiveFeedError("Sensor cannot authorize action")
        cutoff = data["cutoff_epoch_seconds"]
        now = self._clock()
        if (isinstance(cutoff, bool) or not isinstance(cutoff, (int, float))
                or not math.isfinite(cutoff) or cutoff < now - self.MAX_AGE or cutoff > now + 60):
            raise LiveFeedError("Historical/future capture is not live")
        trajectory = data["trajectory"]
        if not isinstance(trajectory, list) or len(trajectory) != 4:
            raise LiveFeedError("Four future horizons required")
        clean = []
        for horizon, row in zip(self.HORIZONS, trajectory):
            if not isinstance(row, dict) or set(row) != {"horizon_seconds", "malicious_flow_probability"}:
                raise LiveFeedError("Invalid trajectory shape")
            p = row["malicious_flow_probability"]
            if (row["horizon_seconds"] != horizon or isinstance(p, bool) or
                    not isinstance(p, (float, int)) or not math.isfinite(p) or not 0 <= p <= 1):
                raise LiveFeedError("Invalid horizon/probability")
            clean.append({"horizon_seconds": horizon, "malicious_flow_probability": round(float(p), 8)})
        with self._lock:
            self._last_id += 1
            event = {
                "id": self._last_id, "kind": "forecast", "source": "completed_capture_shadow",
                "received_at": now, "cutoff_epoch_seconds": float(cutoff),
                "capture_sha256": data["capture_sha256"].lower(),
                "model_sha256": data["model_sha256"].lower(),
                "trajectory": clean,
                "score": round(max(x["malicious_flow_probability"] for x in clean) * 100, 4),
                "alert": data["alert"], "supported": data["supported"],
                "operating_mode": "SHADOW_ONLY", "automatic_containment": False,
                "verified_precompromise": False,
            }
            self._events.append(event)
            return dict(event)

    def snapshot(self, after=0):
        if isinstance(after, bool) or not isinstance(after, int) or not 0 <= after <= 9007199254740991:
            raise LiveFeedError("Invalid cursor")
        with self._lock:
            latest = self._events[-1] if self._events else None
            age = max(0, self._clock() - latest["received_at"]) if latest else None
            state = ("disabled" if not self.enabled else "waiting" if latest is None
                     else "stale" if age > self.STALE_AFTER else "near_live")
            return {
                "state": state, "source": "completed_capture_shadow",
                "stream": "bounded_polling", "automatic_containment": False,
                "cursor": self._last_id,
                "events": [dict(x) for x in self._events if x["id"] > after],
                "sensor_age_seconds": round(age, 1) if age is not None else None,
                "gap": bool(self._events and after > 0 and after < self._events[0]["id"] - 1),
            }
