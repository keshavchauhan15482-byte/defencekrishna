"""Krishna Defence integrated server: Garuda runtime + evidence/policy bridge.

The live checkpoint is resolved through a fail-closed, integrity-pinned runtime bundle
manifest.  The model itself is additionally SHA-256 checked by ForecastService.  Newer
research evidence may decorate the runtime, but it does not silently replace the live
checkpoint until a compatible bundle is explicitly pinned.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from .bundle_manifest import bundle_public_metadata, resolve_active_bundle
from .response import ResponseCoordinator
from .server import App, Handler, Server
from .ui_contract import harden_ui_asset
from .v15_bridge import V15EvidenceBridge

ROOT = Path(__file__).resolve().parents[1]


class IntegratedHandler(Handler):
    """Serve integrated UI assets with V94 fail-closed claim hardening."""

    EXTRA_STATIC = {
        '/pixel.css': ('pixel.css', 'text/css'),
        '/reference.css': ('reference.css', 'text/css'),
    }
    V94_SCRIPT_ASSETS = {
        '/app.js': 'app.js',
        '/reference-live.js': 'reference-live.js',
    }

    def _static_request_allowed(self):
        host = self.headers.get('Host', '')
        if host not in self.server.allowed_hosts:
            self.respond(403, {'error': 'Unexpected host'})
            return False
        origin = self.headers.get('Origin')
        if origin and origin != 'http://' + host:
            self.respond(403, {'error': 'Cross-origin request denied'})
            return False
        return True

    def handle_request(self):
        url = urlsplit(self.path)
        if self.command == 'GET' and url.path in self.V94_SCRIPT_ASSETS:
            if not self._static_request_allowed():
                return None
            name = self.V94_SCRIPT_ASSETS[url.path]
            try:
                source = (Path(__file__).parent / 'ui' / name).read_text(encoding='utf-8')
                source = harden_ui_asset(name, source)
            except (OSError, RuntimeError, UnicodeError):
                return self.respond(503, {'error': 'Integrated UI safety contract unavailable; stale claim surface not served'})
            return self.respond(200, source.encode('utf-8'), 'application/javascript')
        if self.command == 'GET' and url.path in self.EXTRA_STATIC:
            if not self._static_request_allowed():
                return None
            name, mime = self.EXTRA_STATIC[url.path]
            return self.respond(200, (Path(__file__).parent / 'ui' / name).read_bytes(), mime)
        return super().handle_request()


class IntegratedApp(App):
    def __init__(self, artifacts, runtime, reader_token, operator_token, policy_key='', allowed_cidrs=(), enforce=False, lab_automation=False, bundle_metadata=None):
        super().__init__(artifacts, runtime, reader_token, operator_token, policy_key, allowed_cidrs, enforce, lab_automation)
        self.bundle_metadata = dict(bundle_metadata or {})
        self.v15 = V15EvidenceBridge()
        self.response = ResponseCoordinator(
            self.policy,
            lab_automation,
            unknown_auto_approved=self.v15.autonomous_unknown_containment_approved,
        )

    def forecast(self, payload):
        # V94: unlike the strict research API, the integrated console may display an
        # advisory forecast for unsupported/unverified telemetry.  The support result
        # is then enforced fail-closed by ResponseCoordinator before any autonomous
        # Arjuna/Krishna/Sudarshana action can be published.
        forecast = self.service.predict(payload, allow_unsupported_advisory=True)
        forecast['runtime_support']['enforcement_active'] = True
        if not forecast['runtime_support']['supported']:
            forecast['operating_mode'] = 'SHADOW_UNRESOLVED'
            forecast['predicted_attack_stage'] = None
            forecast['stage_trajectory'] = []
            forecast['stage_status'] = 'Unresolved: V94 runtime support gate did not validate this telemetry for stage-specific or autonomous interpretation.'
        forecast = self.v15.decorate_forecast(forecast)
        forecast['runtime_bundle'] = self.bundle_metadata
        forecast['defence_signal'] = self.response.observe(forecast, payload)
        forecast['automatic_containment'] = forecast['defence_signal'].get('policy', {}).get('status') == 'active'
        forecast['containment_scope'] = 'armed_lab_only; V94 runtime support and latest unknown-forecast evidence gates must both approve autonomous containment'
        forecast['krishna_system'] = {
            'garuda_runtime_model': 'integrity-pinned graph forecaster',
            'garuda_latest_evidence': 'research evidence is separate from the pinned runtime checkpoint',
            'arjuna': 'reviewed exact-memory / known-rule path; autonomous action suppressed when runtime support is unresolved',
            'krishna': 'unknown forecast triage; shadow unless runtime-support and evidence gates approve autonomy',
            'sudarshana': 'operator-scoped signed containment / breach escalation; forecast-driven autonomy is support-gated',
        }
        return forecast

    def integrated_status(self):
        support_gate_present = self.service.support_gate is not None
        return {
            'runtime_bundle': self.bundle_metadata,
            'runtime_model': self.service.meta,
            'runtime_model_sha256': self.service.model_hash,
            'runtime_support_gate': {
                'present': support_gate_present,
                'policy': 'validation-fitted support gate required for forecast-driven autonomous action',
                'missing_gate_mode': 'SHADOW_UNRESOLVED',
                'abstention_is_detection': False,
            },
            'v15': self.v15.public_status(),
            'response': self.response.status(),
            'enforcement_enabled': self.policy.enforce,
            'audit_integrity': self.policy.verify(),
        }


def _select_artifacts(override: str | None) -> tuple[Path, dict]:
    pinned = resolve_active_bundle(ROOT)
    metadata = bundle_public_metadata(ROOT)
    if override is None:
        return pinned, metadata
    if os.environ.get('GARUDA_ALLOW_ARTIFACT_OVERRIDE') != '1':
        raise RuntimeError('--artifacts override is disabled; set GARUDA_ALLOW_ARTIFACT_OVERRIDE=1 for explicit research use')
    chosen = Path(override).resolve()
    metadata = {
        **metadata,
        'artifact_directory': str(chosen),
        'override_active': True,
        'claim_scope': 'Explicit research override; not the pinned validated demo bundle.',
    }
    return chosen, metadata


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port', type=int, default=8090)
    p.add_argument('--artifacts', default=None, help='Research-only artifact override; disabled unless GARUDA_ALLOW_ARTIFACT_OVERRIDE=1')
    p.add_argument('--runtime', default='garuda_v3/runtime')
    args = p.parse_args()

    try:
        artifacts, bundle_metadata = _select_artifacts(args.artifacts)
    except RuntimeError as exc:
        p.error(str(exc))

    runtime = Path(args.runtime); runtime.mkdir(parents=True, exist_ok=True); os.chmod(runtime, 0o700)
    credentials = runtime / 'access.json'
    if not credentials.exists():
        with os.fdopen(os.open(credentials,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as f:
            json.dump(dict(viewer_token=secrets.token_urlsafe(32),operator_token=secrets.token_urlsafe(32)),f)
    access=json.loads(credentials.read_text())
    app=IntegratedApp(
        artifacts,
        runtime,
        os.environ.get('GARUDA_READ_TOKEN', access['viewer_token']),
        os.environ.get('GARUDA_OPERATOR_TOKEN', access['operator_token']),
        os.environ.get('GARUDA_POLICY_KEY', ''),
        [c for c in os.environ.get('GARUDA_ALLOWED_CIDRS', '').split(',') if c],
        os.environ.get('GARUDA_ENFORCE') == '1',
        os.environ.get('GARUDA_LAB_AUTOMATION') == '1',
        bundle_metadata=bundle_metadata,
    )
    server = Server(('127.0.0.1', args.port), app)
    server.RequestHandlerClass = IntegratedHandler
    print(
        f"Krishna Defence + Garuda pinned bundle {bundle_metadata.get('bundle_id')}: "
        f"http://127.0.0.1:{server.server_port}. Dry-run by default.",
        flush=True,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close(); app.policy.close()


if __name__ == '__main__':
    main()
