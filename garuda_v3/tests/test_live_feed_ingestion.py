"""Security and correctness checks for near-live sensor ingestion."""
import http.client
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from garuda_v3.live_feed import LiveFeed, LiveFeedError
from garuda_v3.live_publisher import event_from_result, read_private_token, validate_endpoint
from garuda_v3.server import Server
from garuda_v3.integrated_server import IntegratedHandler


TOKEN = "sensor-" + "Z" * 40


def make_event(now=None):
    return {
        "schema": "krishna-live-v1",
        "kind": "forecast",
        "capture_sha256": "a" * 64,
        "model_sha256": "b" * 64,
        "cutoff_epoch_seconds": time.time() - 1 if now is None else now - 1,
        "trajectory": [
            {"horizon_seconds": n, "malicious_flow_probability": 0.1 + i / 10}
            for i, n in enumerate((10, 20, 30, 40))
        ],
        "alert": True,
        "supported": False,
        "automatic_containment": False,
    }


class LiveFeedTests(unittest.TestCase):
    def test_disabled_waiting_near_live_and_stale(self):
        clock = [1000.0]
        disabled = LiveFeed(clock=lambda: clock[0])
        self.assertEqual(disabled.snapshot()["state"], "disabled")
        with self.assertRaises(LiveFeedError):
            disabled.append(make_event(1000))
        feed = LiveFeed(TOKEN, clock=lambda: clock[0])
        self.assertEqual(feed.snapshot()["state"], "waiting")
        self.assertFalse(feed.authorized("Bearer invalid"))
        self.assertFalse(feed.authorized("Bearer " + TOKEN[:-1]))
        self.assertTrue(feed.authorized("Bearer " + TOKEN))
        event = feed.append(make_event(1000))
        self.assertEqual(event["score"], 40)
        self.assertEqual(event["operating_mode"], "SHADOW_ONLY")
        self.assertFalse(event["automatic_containment"])
        self.assertEqual(feed.snapshot()["state"], "near_live")
        self.assertEqual(feed.snapshot(after=event["id"])["events"], [])
        clock[0] += 121
        self.assertEqual(feed.snapshot()["state"], "stale")

    def test_rejects_replays_malformed_spoofed_containment_and_nan(self):
        clock = [1000.0]
        feed = LiveFeed(TOKEN, clock=lambda: clock[0])
        for edit in (
            {"cutoff_epoch_seconds": 1},
            {"cutoff_epoch_seconds": 100000},
            {"automatic_containment": True},
            {"capture_sha256": "invalid"},
            {"trajectory": []},
            {"trajectory": [{**x, "malicious_flow_probability": float("nan")}
                            for x in make_event(1000)["trajectory"]]},
            {"supported": "yes"},
            {"alert": 1},
        ):
            payload = make_event(1000)
            payload.update(edit)
            with self.subTest(edit=edit), self.assertRaises(LiveFeedError):
                feed.append(payload)
        self.assertEqual(feed.snapshot()["events"], [])

    def test_packet_trained_sixty_second_horizons_are_accepted(self):
        clock=[1000.0]
        feed=LiveFeed(TOKEN,clock=lambda:clock[0])
        payload=make_event(1000)
        payload["trajectory"]=[
            {"horizon_seconds":w,"malicious_flow_probability":v}
            for w,v in ((60,.1),(120,.2),(180,.3),(240,.4))]
        event=feed.append(payload)
        self.assertEqual([t["horizon_seconds"] for t in event["trajectory"]],[60,120,180,240])
        bad=make_event(1000)
        bad["trajectory"]=payload["trajectory"].copy()
        bad["trajectory"][-1]={"horizon_seconds":40,"malicious_flow_probability":.4}
        with self.assertRaises(LiveFeedError):
            feed.append(bad)

    def test_bounded_history_and_cursor_gap(self):
        feed = LiveFeed(TOKEN, clock=lambda: 1000.0)
        for _ in range(133):
            feed.append(make_event(1000))
        result = feed.snapshot(after=1)
        self.assertTrue(result["gap"])
        self.assertEqual(len(result["events"]), 128)
        with self.assertRaises(LiveFeedError):
            feed.snapshot(after=-1)


class PublisherTests(unittest.TestCase):
    def test_url_restriction_and_token_file(self):
        self.assertEqual(validate_endpoint("http://127.0.0.1:8090/api/live/ingest").path,
                         "/api/live/ingest")
        self.assertEqual(validate_endpoint("https://sensor.example/api/live/ingest").scheme, "https")
        for bad in ("http://example.com/api/live/ingest",
                    "http://127.0.0.1:8090/api/live/ingest?x=y",
                    "https://username:password@example.com/api/live/ingest",
                    "file:///api/live/ingest"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_endpoint(bad)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sensor.key"
            path.write_text(TOKEN)
            path.chmod(0o600)
            self.assertEqual(read_private_token(path), TOKEN)
            if path.is_symlink() is False:
                alias = Path(folder) / "alias"
                alias.symlink_to(path)
                with self.assertRaises(ValueError):
                    read_private_token(alias)

    def test_derived_event_never_contains_enforcement_or_packet_content(self):
        r = {"status": "forecast", "capture_sha256": "a" * 64,
             "model_sha256": "b" * 64, "cutoff_epoch_seconds": 999,
             "trajectory": make_event(1000)["trajectory"], "alert": True,
             "runtime_support": {"supported": False}, "node_names": ["192.0.2.4"]}
        event = event_from_result(r)
        self.assertFalse(event["automatic_containment"])
        self.assertFalse(event["supported"])
        self.assertNotIn("node_names", event)


class HTTPIntegrationTests(unittest.TestCase):
    def test_real_http_ingest_and_pilot_boundary(self):
        app = SimpleNamespace(
            live_feed=LiveFeed(TOKEN),
            deployment_profile="pilot",
            rate_ok=lambda _: True,
            role=lambda value: "viewer" if value == "viewer" else None,
        )
        server = Server(("127.0.0.1", 0), app)
        server.RequestHandlerClass = IntegratedHandler
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        port = server.server_port

        def request(method, path, token=None, body=None, origin=None):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            headers = {}
            if token is not None:
                headers["Authorization"] = "Bearer " + token
            if body is not None:
                headers["Content-Type"] = "application/json"
            if origin is not None:
                headers["Origin"] = origin
            try:
                conn.request(method, path, body=body, headers=headers)
                response = conn.getresponse()
                return response.status, json.loads(response.read())
            finally:
                conn.close()

        try:
            payload = json.dumps(make_event()).encode()
            self.assertEqual(request("POST", "/api/live/ingest", "bad", payload)[0], 401)
            self.assertEqual(request("POST", "/api/live/ingest", TOKEN, payload,
                                     origin="https://evil.example")[0], 403)
            status, accepted = request("POST", "/api/live/ingest", TOKEN, payload)
            self.assertEqual(status, 202)
            self.assertTrue(accepted["accepted"])
            self.assertEqual(request("GET", "/bridge/live/events?after=0")[0], 401)
            status, feed = request("GET", "/bridge/live/events?after=0", "viewer")
            self.assertEqual(status, 200)
            self.assertEqual(len(feed["events"]), 1)
            self.assertEqual(feed["events"][0]["operating_mode"], "SHADOW_ONLY")
            payload2 = make_event()
            payload2["automatic_containment"] = True
            self.assertEqual(request("POST", "/api/live/ingest", TOKEN,
                                     json.dumps(payload2).encode())[0], 422)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
