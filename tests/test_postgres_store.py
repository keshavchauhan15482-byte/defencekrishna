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
        if key.startswith("CREATE"): return
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
