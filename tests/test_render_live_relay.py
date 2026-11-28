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

    def test_root_landing_explains_backend_is_api_not_website(self):
        for path in ("/", "/status"):
            conn=http.client.HTTPConnection("127.0.0.1",self.server.server_port,timeout=5)
            try:
                conn.request("GET",path)
                response=conn.getresponse()
                content_type=response.getheader("Content-Type","")
                body=response.read().decode("utf-8")
                self.assertEqual(response.status,200)
                self.assertIn("text/html",content_type)
                self.assertIn("Backend online",body)
                self.assertIn("Open Krishna Defence dashboard",body)
                self.assertIn("Awaiting an authorized network capture sensor",body)
                self.assertNotIn(SENSOR,body)
                self.assertNotIn(VIEWER,body)
            finally:
                conn.close()

    def test_health_and_authenticated_read(self):
        code, payload = self.request("GET", "/health")
        self.assertEqual(code, 200)
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(self.request("GET", "/api/sensor/verify")[0], 401)
        self.assertEqual(self.request("GET", "/api/sensor/verify", token=VIEWER)[0], 401)
        code, verified = self.request("GET", "/api/sensor/verify", token=SENSOR)
        self.assertEqual(code, 200)
        self.assertTrue(verified["authorized"])
        self.assertFalse(verified.get("automatic_containment", False))
        self.assertNotIn("sensor_token", verified)
        self.assertEqual(self.request("GET", "/api/live/events")[0], 401)
        self.assertEqual(self.request("GET", "/api/live/events", token=SENSOR)[0], 401)
        self.assertEqual(self.request("GET", "/api/live/events?after=-1", token=VIEWER)[0], 422)
        self.assertEqual(self.request("GET", "/api/live/events", token=VIEWER)[1]["state"], "waiting")


    def test_private_cloud_inference_readiness_and_graph_auth(self):
        self.assertEqual(self.request("GET","/api/cloud-inference/status")[0],401)
        self.assertEqual(self.request("POST","/api/cloud-inference/graph",{})[0],401)
        self.assertEqual(self.request("POST","/api/cloud-inference/graph",{},token=VIEWER)[0],401)
        self.assertEqual(self.request("POST","/api/cloud-inference/graph",{},token=SENSOR)[0],422)
        code,body=self.request("GET","/api/cloud-inference/status",token=VIEWER)
        self.assertEqual(code,200)
        self.assertEqual(body["status"],"ready")
        self.assertFalse(body["live_prediction"])
        self.assertFalse(body["automatic_containment"])
        self.assertIs(body["support_gate_configured"],False)
        self.assertGreater(body["history_seconds"],0)
        self.assertIn(body["window_seconds"],(10,60))

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

    def test_independent_site_traffic_ingest_requires_a_third_token(self):
        from garuda_v3.live_feed import LiveFeedError

        activity_token="activity-"+"Z"*40
        with self.assertRaises(ValueError):
            RelayState(SENSOR,VIEWER,activity_token=VIEWER)

        class ActivityStore:
            def __init__(self):
                self.requests=[]
                self.heartbeat=None
            def record_sensor_heartbeat(self,data):
                if data.get('kind')!='heartbeat':raise LiveFeedError('Invalid heartbeat')
                self.heartbeat=data
                return {'accepted':True,'mode':'SHADOW_CAPTURE_HEARTBEAT'}
            def sensor_status_snapshot(self):
                return {'state':self.heartbeat['state'] if self.heartbeat else 'absent',
                        'sensor_age_seconds':0 if self.heartbeat else None,
                        'capture_seconds':self.heartbeat['capture_seconds'] if self.heartbeat else None,
                        'source':'authenticated_sensor_heartbeat'}
            def record_site_request(self,data):
                if set(data)!={"schema","kind","request_uuid"} or data["kind"]!="page_load":
                    raise LiveFeedError("Invalid site activity")
                self.requests.append(data)
                return {"accepted":True,"stored":True,"mode":"HTTP_ACTIVITY_ONLY"}
            def snapshot(self,after):
                return {"state":"waiting","events":[],"cursor":0,
                        "sensor_age_seconds":None,"gap":False}
            def site_activity_snapshot(self):
                return {"source":"first_party_page_requests","total_requests":len(self.requests),
                        "requests_24h":len(self.requests),"last_request_at":time.time(),
                        "is_model_input":False}
        store=ActivityStore()
        self.app.activity_token=activity_token
        self.app.store=store
        data={"schema":"krishna-site-activity-v1","kind":"page_load",
              "request_uuid":"01234567-89ab-4cde-8f01-23456789abcd"}
        self.assertEqual(self.request("POST","/api/site-activity/ingest",data)[0],401)
        self.assertEqual(self.request("POST","/api/site-activity/ingest",data,token=SENSOR)[0],401)
        self.assertEqual(self.request("POST","/api/site-activity/ingest",data,token=activity_token)[0],202)
        self.assertEqual(self.request("POST","/api/site-activity/ingest",{**data,"kind":"attack"},token=activity_token)[0],422)
        self.assertEqual(len(store.requests),1)
        code,feed=self.request("GET","/api/live/events",token=VIEWER)
        self.assertEqual(code,200)
        self.assertEqual(feed["state"],"waiting")
        self.assertEqual(feed["site_activity"]["total_requests"],1)
        self.assertFalse(feed["site_activity"]["is_model_input"])
        heartbeat={'schema':'krishna-sensor-heartbeat-v1','kind':'heartbeat',
                   'state':'capturing','capture_seconds':600,'model_sha256':'a'*64}
        self.assertEqual(self.request("POST","/api/sensor/heartbeat",heartbeat)[0],401)
        self.assertEqual(self.request("POST","/api/sensor/heartbeat",heartbeat,token=VIEWER)[0],401)
        self.assertEqual(self.request("POST","/api/sensor/heartbeat",heartbeat,token=SENSOR)[0],202)
        code,feed=self.request("GET","/api/live/events",token=VIEWER)
        self.assertEqual(code,200)
        self.assertEqual(feed["sensor_status"]["state"],"capturing")
        self.assertEqual(feed["sensor_status"]["capture_seconds"],600)
        self.assertNotIn("model_sha256",feed["sensor_status"])

    def test_no_cors_or_public_inference_endpoint(self):
        self.assertEqual(self.request("OPTIONS", "/api/live/ingest")[0], 405)
        self.assertEqual(self.request("GET", "/api/forecast", token=SENSOR)[0], 404)
        self.assertEqual(self.request("POST", "/api/policy/create", sample(), token=SENSOR)[0], 404)


if __name__ == "__main__":
    unittest.main()
