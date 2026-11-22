"""End-to-end HTTP checks for Render's metadata-only Garuda relay."""
import http.client
import json
import threading
import time
import unittest

from deployment.render.live_relay import RelayServer, RelayState


SENSOR = "sensor-" + "x" * 40
VIEWER = "viewer-" + "y" * 40


def sample():
    return {
        "schema": "krishna-live-v1",
        "kind": "forecast",
        "capture_sha256": "a" * 64,
        "model_sha256": "b" * 64,
        "cutoff_epoch_seconds": time.time() - 1,
        "trajectory": [
            {"horizon_seconds": s, "malicious_flow_probability": v}
            for s, v in ((10, .1), (20, .2), (30, .3), (40, .4))
        ],
        "alert": True,
        "supported": False,
        "automatic_containment": False,
    }


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.app = RelayState(SENSOR, VIEWER)
        self.server = RelayServer(("127.0.0.1", 0), self.app)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=5)

    def request(self, method, path, payload=None, token=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        h = dict(headers or {})
        if token is not None:
            h["Authorization"] = "Bearer " + token
        raw = json.dumps(payload).encode() if payload is not None else None
        if raw is not None:
            h["Content-Type"] = "application/json"
        try:
            conn.request(method, path, body=raw, headers=h)
            response = conn.getresponse()
            body = json.loads(response.read())
            return response.status, body
        finally:
            conn.close()

    def test_health_and_authenticated_read(self):
        code, payload = self.request("GET", "/health")
        self.assertEqual(code, 200)
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(self.request("GET", "/api/live/events")[0], 401)
        self.assertEqual(self.request("GET", "/api/live/events", token=SENSOR)[0], 401)
        self.assertEqual(self.request("GET", "/api/live/events?after=-1", token=VIEWER)[0], 422)
        self.assertEqual(self.request("GET", "/api/live/events", token=VIEWER)[1]["state"], "waiting")

    def test_sensor_auth_projection_replay_and_shadow_only(self):
        evt = sample()
        self.assertEqual(self.request("POST", "/api/live/ingest", evt)[0], 401)
        self.assertEqual(self.request("POST", "/api/live/ingest", evt, token=VIEWER)[0], 401)
        code, accepted = self.request("POST", "/api/live/ingest", evt, token=SENSOR)
        self.assertEqual(code, 202)
        self.assertTrue(accepted["accepted"])
        event_id = accepted["event_id"]
        code, feed = self.request("GET", "/api/live/events?after=0", token=VIEWER)
        self.assertEqual(code, 200)
        self.assertEqual(feed["state"], "near_live")
        self.assertEqual(len(feed["events"]), 1)
        self.assertEqual(feed["events"][0]["operating_mode"], "SHADOW_ONLY")
        self.assertFalse(feed["events"][0]["automatic_containment"])
        self.assertNotIn("capture_sha256", feed["events"][0])
        self.assertNotIn("model_sha256", feed["events"][0])
        # Exact same capture retry is idempotent.
        code, duplicate = self.request("POST", "/api/live/ingest", evt, token=SENSOR)
        self.assertEqual(code, 202)
        self.assertEqual(duplicate["event_id"], event_id)
        self.assertEqual(self.request("GET", "/api/live/events", token=VIEWER)[1]["cursor"], 1)
        bad = dict(evt, automatic_containment=True)
        self.assertEqual(self.request("POST", "/api/live/ingest", bad, token=SENSOR)[0], 422)
        old = dict(evt, cutoff_epoch_seconds=time.time() - 1000)
        self.assertEqual(self.request("POST", "/api/live/ingest", old, token=SENSOR)[0], 422)
        altered = dict(evt, alert=False)
        self.assertEqual(self.request("POST", "/api/live/ingest", altered, token=SENSOR)[0], 422)

    def test_no_cors_or_public_inference_endpoint(self):
        self.assertEqual(self.request("OPTIONS", "/api/live/ingest")[0], 405)
        self.assertEqual(self.request("GET", "/api/forecast", token=SENSOR)[0], 404)
        self.assertEqual(self.request("POST", "/api/policy/create", sample(), token=SENSOR)[0], 404)


if __name__ == "__main__":
    unittest.main()
