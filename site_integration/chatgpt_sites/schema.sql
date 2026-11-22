-- ChatGPT Sites D1 migration for Krishna's isolated advisory telemetry feed.
-- Apply through the existing Site's migration workflow. Do NOT replace the
-- site's existing D1 schema or data.
CREATE TABLE IF NOT EXISTS krishna_live_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  received_at REAL NOT NULL,
  cutoff_epoch_seconds REAL NOT NULL,
  capture_sha256 TEXT NOT NULL,
  model_sha256 TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  UNIQUE (capture_sha256, model_sha256)
);

CREATE INDEX IF NOT EXISTS idx_krishna_live_received
  ON krishna_live_events(received_at);
