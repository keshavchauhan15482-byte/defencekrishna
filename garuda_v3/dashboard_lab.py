"""Isolated HTTP probe policy. Never changes enterprise or Garuda authorization."""
import math
import secrets
import threading
import time

class DashboardLab:
    def __init__(self):
        self.lock = threading.Lock()
        self.tickets = {}
        self.confirmed = 0

    def issue(self, forecast):
        values = [p.get("malicious_flow_probability") for p in forecast.get("trajectory", [])]
        valid = bool(values) and all(isinstance(v, (int, float)) and not isinstance(v, bool)
                                    and math.isfinite(v) and 0 <= v <= 1 for v in values)
        signal = forecast.get("defence_signal") or {}
        # Unknown forecast authorization is not bypassed by the demonstration.
        permitted = signal.get("route") == "arjuna"
        blocked = valid and max(values) >= .75 and permitted
        with self.lock:
            now = time.monotonic()
            self.tickets = {k:v for k,v in self.tickets.items() if v["expires"] > now}
            if len(self.tickets) >= 256:
                raise ValueError("Lab probe capacity reached")
            token = secrets.token_urlsafe(24)
            self.tickets[token] = dict(blocked=blocked, valid=valid, expires=now+60, counted=False)
        return dict(ticket=token, scope="local HTTP probe only", threshold=.75,
                    decision="block" if blocked else "review" if valid and max(values)>=.75 else "pass" if valid else "abstain")

    def probe(self, token):
        with self.lock:
            row = self.tickets.get(token)
            if row is None or row["expires"] <= time.monotonic():
                return 410, dict(error="Probe ticket missing or expired")
            if not row["valid"]:
                return 422, dict(error="Insufficient forecast evidence")
            if row["blocked"] and not row["counted"]:
                self.confirmed += 1
                row["counted"] = True
            return (403 if row["blocked"] else 200), dict(
                enforcement_confirmed=row["blocked"],
                scope="local HTTP probe only", confirmed_blocks=self.confirmed)

LAB = DashboardLab()
