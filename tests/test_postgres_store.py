"""DB-backed observation persistence contract without a live DB dependency."""
import copy
import json
import time
import unittest
from deployment.render.postgres_store import PostgresEventStore
from garuda_v3.live_feed import LiveFeedError

TOKEN = "sensor-" + "q" * 40


class FakeDb:
    def __init__(self):
        self.records = []
        self.next_id = 1
        self.activity = []
        self.next_activity_id = 1
        self.heartbeat = None
        self.receipts = {}
        self.patterns = {}

    def connect(self, _dsn):
        return FakeConnection(self)


class FakeConnection:
    def __init__(self, db):
        self.db = db
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        return False
    def cursor(self):
        return FakeCursor(self.db)


class FakeCursor:
    def __init__(self, db):
        self.db = db
        self.last = None
        self.list_results = []
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        return False
    def execute(self, sql, params=()):
        key = " ".join(sql.split()).upper()
        self.last = None
        self.list_results = []
        if key.startswith("CREATE") or key.startswith("LOCK TABLE"): return
        if key.startswith("SELECT LANE,REASON,LEAST(COUNT(*)"):
            grouped={}
            for lane,reason,at in self.db.receipts.values():
                count,last=grouped.get((lane,reason),(0,at))
                grouped[(lane,reason)]=(min(8,count+1),max(last,at))
            self.list_results=[(lane,reason,count,last) for (lane,reason),(count,last) in grouped.items()]
            return
        if key.startswith("DELETE FROM KRISHNA_FIXTURE_"): return
        if key.startswith("INSERT INTO KRISHNA_FIXTURE_RECEIPTS"):
            uuid,at,lane,reason=params
            if uuid not in self.db.receipts:
                self.db.receipts[uuid]=(lane,reason,at)
                self.last=(len(self.db.receipts),)
            return
        if key.startswith("INSERT INTO KRISHNA_FIXTURE_DENIAL_BUCKETS"): return
        if key.startswith("INSERT INTO KRISHNA_DEMO_PATTERN_MEMORY"):
            if len(params)==4:
                lane,reason,count,last=params
                old=self.db.patterns.get((lane,reason),(0,last))
                self.db.patterns[(lane,reason)]=(max(count,old[0]),max(last,old[1]))
            else:
                lane,reason,last=params
                old=self.db.patterns.get((lane,reason),(0,last))
                self.db.patterns[(lane,reason)]=(min(8,old[0]+1),max(last,old[1]))
            return
        if key.startswith("SELECT LANE,REASON,CONFIRMATIONS,LAST_SEEN"):
            self.list_results=[(lane,reason,count,last) for (lane,reason),(count,last) in self.db.patterns.items()]
            return
        if key.startswith("INSERT INTO KRISHNA_SENSOR_HEARTBEAT"):
            seen,state,duration,model=params
            self.db.heartbeat=(seen,state,duration,model)
            return
        if key.startswith("SELECT SEEN_AT,STATE,CAPTURE_SECONDS"):
            self.last=self.db.heartbeat[:3] if self.db.heartbeat else None
            return
        if key.startswith("INSERT INTO KRISHNA_SITE_ACTIVITY_EVENTS"):
            request_uuid, observed_at = params
            if not any(row["uuid"] == request_uuid for row in self.db.activity):
                self.db.activity.append({"id":self.db.next_activity_id,"uuid":request_uuid,"at":observed_at})
                self.last=(self.db.next_activity_id,)
                self.db.next_activity_id+=1
            return
        if key.startswith("SELECT COUNT(*)::BIGINT"):
            cutoff = params[0]
            times = [row["at"] for row in self.db.activity]
            _, recent, prior, boundary = params
            self.last=(len(times),len([x for x in times if x>=cutoff]),max(times,default=None),
                       len([x for x in times if x>=recent]),
                       len([x for x in times if prior<=x<boundary]))
            return
        if key.startswith("INSERT"):
            h, m, received, cutoff, raw = params
            if not any(row["h"] == h and row["m"] == m for row in self.db.records):
                self.db.records.append({"id": self.db.next_id, "h": h, "m": m,
                                        "received": received, "cutoff": cutoff,
                                        "event": json.loads(raw)})
                self.last = (self.db.next_id,)
                self.db.next_id += 1
            return
        if key.startswith("UPDATE"):
            data, id_ = params
            row = next(row for row in self.db.records if row["id"] == id_)
            row["event"] = json.loads(data)
            return
        if "WHERE CAPTURE_SHA256" in key:
            h, m = params
            row = next((row for row in self.db.records if row["h"] == h and row["m"] == m), None)
            self.last = (row["id"], copy.deepcopy(row["event"])) if row else None
        elif "SELECT ID,RECEIVED_AT" in key:
            self.last = (self.db.records[-1]["id"], self.db.records[-1]["received"]) if self.db.records else None
        elif "SELECT ID FROM" in key:
            self.last = (self.db.records[0]["id"],) if self.db.records else None
        elif "SELECT EVENT_JSON" in key:
            after = params[0]
            self.list_results = [(copy.deepcopy(row["event"]),) for row in self.db.records if row["id"] > after][:128]
        else:
            raise AssertionError("Unexpected SQL")
    def fetchone(self):
        return self.last
    def fetchall(self):
        return self.list_results


def event(now):
    return {
        "schema": "krishna-live-v1", "kind": "forecast",
        "capture_sha256": "a" * 64, "model_sha256": "b" * 64,
        "cutoff_epoch_seconds": now - 1,
        "trajectory": [
            {"horizon_seconds": h, "malicious_flow_probability": p}
            for h, p in ((10, .1), (20, .2), (30, .3), (40, .4))
        ],
        "alert": True, "supported": False, "automatic_containment": False,
    }


class PersistentStoreTests(unittest.TestCase):
    def test_independent_database_preserves_events_after_restart(self):
        clock = [1000.0]
        db = FakeDb()
        make = lambda: PostgresEventStore(
            "postgresql://placeholder/test", TOKEN, connect=db.connect, clock=lambda: clock[0])
        first = make()
        observation = event(clock[0])
        saved = first.accept(observation)
        self.assertEqual(saved["id"], 1)
        self.assertEqual(saved["operating_mode"], "SHADOW_ONLY")
        self.assertFalse(saved["automatic_containment"])
        self.assertEqual(len(db.records), 1)
        restarted = make()
        self.assertEqual(restarted.snapshot()["state"], "near_live")
        self.assertEqual(restarted.snapshot()["events"][0]["id"], 1)
        self.assertEqual(restarted.accept(observation)["id"], 1)
        self.assertEqual(len(db.records), 1)
        conflict = {**observation, "alert": False}
        with self.assertRaises(LiveFeedError):
            restarted.accept(conflict)
        self.assertEqual(len(db.records), 1)
        clock[0] += 121
        self.assertEqual(restarted.snapshot()["state"], "stale")
        with self.assertRaises(LiveFeedError):
            restarted.accept({**observation, "cutoff_epoch_seconds": 1})
        self.assertEqual(len(db.records), 1)

    def test_real_page_requests_persist_independently_of_training(self):
        clock=[1000.0]
        db=FakeDb()
        make=lambda: PostgresEventStore("postgresql://placeholder/test",TOKEN,
                                      connect=db.connect,clock=lambda:clock[0])
        store=make()
        entry={"schema":"krishna-site-activity-v1","kind":"page_load",
               "request_uuid":"01234567-89ab-4cde-8f01-23456789abcd"}
        r=store.record_site_request(entry)
        self.assertTrue(r["stored"])
        self.assertEqual(len(db.activity),1)
        self.assertEqual(len(db.records),0)
        r=make().record_site_request(entry)
        self.assertFalse(r["stored"])
        counts=make().site_activity_snapshot()
        self.assertEqual(counts["total_requests"],1)
        self.assertEqual(counts["requests_24h"],1)
        self.assertEqual(counts["requests_5m"],1)
        self.assertEqual(counts["requests_previous_5m"],0)
        clock[0]+=300.1
        counts=make().site_activity_snapshot()
        self.assertEqual(counts["requests_5m"],0)
        self.assertEqual(counts["requests_previous_5m"],1)
        self.assertEqual(counts["last_request_at"],1000)
        self.assertFalse(counts["is_model_input"])
        for bad in (
            {**entry,"user_ip":"127.0.0.1"},
            {**entry,"kind":"attack"},
            {**entry,"request_uuid":"user-identifier"},
        ):
            with self.assertRaises(LiveFeedError):
                store.record_site_request(bad)
        self.assertEqual(len(db.activity),1)
        clock[0]+=86401
        self.assertEqual(make().site_activity_snapshot()["requests_24h"],0)
        self.assertEqual(make().site_activity_snapshot()["total_requests"],1)

    def test_real_sensor_heartbeat_is_separate_from_predictions(self):
        clock=[1000.0]
        db=FakeDb()
        make=lambda:PostgresEventStore("postgresql://placeholder/test",TOKEN,
                  connect=db.connect,clock=lambda:clock[0])
        store=make()
        heartbeat={"schema":"krishna-sensor-heartbeat-v1","kind":"heartbeat",
                   "state":"capturing","capture_seconds":600,"model_sha256":"a"*64}
        self.assertEqual(store.sensor_status_snapshot()["state"],"absent")
        self.assertTrue(store.record_sensor_heartbeat(heartbeat)["accepted"])
        self.assertEqual(len(db.records),0)
        self.assertEqual(len(db.activity),0)
        newer=make()
        status=newer.sensor_status_snapshot()
        self.assertEqual(status["state"],"capturing")
        self.assertEqual(status["capture_seconds"],600)
        self.assertNotIn("model_sha256",status)
        for bad in ({**heartbeat,"state":"blocked"},
                    {**heartbeat,"capture_seconds":0},
                    {**heartbeat,"source_ip":"private"}):
            with self.assertRaises(LiveFeedError):
                newer.record_sensor_heartbeat(bad)
        clock[0]+=91
        self.assertEqual(make().sensor_status_snapshot()["state"],"stale")
        self.assertEqual(len(db.records),0)

    def test_existing_receipts_backfill_idempotent(self):
        db=FakeDb()
        db.receipts={"a":("ARJUNA","DEMO_PORT_SCAN",998.),
                     "b":("ARJUNA","DEMO_PORT_SCAN",999.),
                     "c":("KRISHNA","DEMO_DNS_TUNNEL",999.),
                     "d":("KRISHNA","UNSPECIFIED_RULE",999.)}
        store=lambda:PostgresEventStore("postgresql://placeholder/test",TOKEN,connect=db.connect,clock=lambda:1000.)
        for _ in range(3):
            state=store().pattern_memory_snapshot()
            self.assertEqual(state["patterns_saved"],2)
            self.assertEqual(state["candidate_revisions"],1)
        store().record_fixture_denial({"schema":"fixture-denial-v2","request_uuid":"00000000-0000-4000-8000-000000000005","lane":"ARJUNA","reason":"DEMO_PORT_SCAN"})
        state=store().pattern_memory_snapshot()
        self.assertEqual(next(p for p in state["profiles"] if p["reason"]=="DEMO_PORT_SCAN")["confirmations"],3)
        self.assertEqual(state["candidate_revisions"],1)

    def test_fixture_memory_dedup_and_versions(self):
        db=FakeDb()
        store=lambda:PostgresEventStore("postgresql://placeholder/test",TOKEN,connect=db.connect,clock=lambda:1000.)
        def entry(i,reason="DEMO_DNS_TUNNEL"):
            return {"schema":"fixture-denial-v2","request_uuid":f"00000000-0000-4000-8000-{i:012x}","lane":"KRISHNA","reason":reason}
        self.assertEqual(store().pattern_memory_snapshot()["patterns_saved"],0)
        store().record_fixture_denial(entry(1))
        store().record_fixture_denial(entry(1))
        self.assertEqual(store().pattern_memory_snapshot()["profiles"][0]["confirmations"],1)
        store().record_fixture_denial(entry(2))
        self.assertEqual(store().pattern_memory_snapshot()["candidate_revisions"],1)
        for i in range(3,12):store().record_fixture_denial(entry(i))
        p=store().pattern_memory_snapshot()
        self.assertEqual(p["patterns_saved"],1)
        self.assertEqual(p["candidate_revisions"],3)
        self.assertEqual(p["profiles"][0]["confirmations"],8)
        self.assertFalse(p["model_retrained"])
        store().record_fixture_denial(entry(12,"UNSPECIFIED_RULE"))
        self.assertEqual(store().pattern_memory_snapshot()["patterns_saved"],1)
        with self.assertRaises(LiveFeedError):store().record_fixture_denial(entry(13,"UNREVIEWED"))
        self.assertEqual(store().pattern_memory_snapshot()["patterns_saved"],1)

    def test_no_training_data_or_raw_packets_in_persistent_events(self):
        db = FakeDb()
        store = PostgresEventStore("postgresql://placeholder/test", TOKEN,
                                   connect=db.connect, clock=lambda: 1000.0)
        original = event(1000)
        store.accept(original)
        saved = store.snapshot()["events"][0]
        self.assertNotIn("packet_bytes", saved)
        self.assertNotIn("training_labels", saved)
        self.assertNotIn("model_weights", saved)
        for key in ("capture_sha256", "model_sha256", "cutoff_epoch_seconds",
                    "trajectory", "received_at"):
            self.assertIn(key, saved)
        with self.assertRaises(LiveFeedError):
            store.accept({**original, "packet_bytes": "private"})
        self.assertEqual(len(db.records), 1)


if __name__ == "__main__":
    unittest.main()
