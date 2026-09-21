from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from garuda_v3.bundle_manifest import git_blob_sha1, resolve_active_bundle


class RuntimeBundleManifestTests(unittest.TestCase):
    REQUIRED = {
        "gnn_lstm.npz": b"checkpoint",
        "metrics.json": b"{}",
        "replay.json": b"{}",
        "alert_replay.json": b"{}",
    }

    def make_root(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        bundle = root / "garuda_v3" / "artifacts" / "candidate"
        bundle.mkdir(parents=True)
        files = {}
        for name, raw in self.REQUIRED.items():
            (bundle / name).write_bytes(raw)
            files[name] = git_blob_sha1(raw)
        manifest = {
            "schema_version": 1,
            "status": "validated-runtime-input",
            "bundle_id": "unit-test",
            "artifact_directory": "garuda_v3/artifacts/candidate",
            "files": files,
        }
        (root / "garuda_v3" / "active_runtime_bundle.json").write_text(json.dumps(manifest))
        return td, root, bundle, manifest

    def test_valid_bundle_resolves(self):
        td, root, bundle, _ = self.make_root()
        try:
            self.assertEqual(resolve_active_bundle(root), bundle.resolve())
        finally:
            td.cleanup()

    def test_tampered_file_fails_closed(self):
        td, root, bundle, _ = self.make_root()
        try:
            (bundle / "gnn_lstm.npz").write_bytes(b"tampered")
            with self.assertRaisesRegex(RuntimeError, "integrity mismatch"):
                resolve_active_bundle(root)
        finally:
            td.cleanup()

    def test_path_escape_fails_closed(self):
        td, root, _, manifest = self.make_root()
        try:
            outside = root / "outside"
            outside.mkdir()
            for name, raw in self.REQUIRED.items():
                (outside / name).write_bytes(raw)
            manifest["artifact_directory"] = "outside"
            (root / "garuda_v3" / "active_runtime_bundle.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(RuntimeError, "escapes garuda_v3/artifacts"):
                resolve_active_bundle(root)
        finally:
            td.cleanup()

    def test_missing_required_manifest_entry_fails_closed(self):
        td, root, _, manifest = self.make_root()
        try:
            manifest["files"].pop("alert_replay.json")
            (root / "garuda_v3" / "active_runtime_bundle.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(RuntimeError, "missing required files"):
                resolve_active_bundle(root)
        finally:
            td.cleanup()

    def test_unsafe_nested_file_name_fails_closed(self):
        td, root, _, manifest = self.make_root()
        try:
            manifest["files"]["../escape"] = "0" * 40
            (root / "garuda_v3" / "active_runtime_bundle.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(RuntimeError, "Unsafe Garuda bundle file name"):
                resolve_active_bundle(root)
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
