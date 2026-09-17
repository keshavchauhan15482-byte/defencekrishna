"""Krishna Defence integrated server: Garuda v3 runtime + V15 evidence/policy bridge.

The existing hash-checked 10-second graph checkpoint remains the live inference
model until a V15 checkpoint is trained on a compatible network-only schema.
V15 is nevertheless integrated into the real forecast/response path as the
latest measured evidence and a fail-closed authority gate.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from .response import ResponseCoordinator
from .server import App, Handler, Server
from .v15_bridge import V15EvidenceBridge


class IntegratedHandler(Handler):
    """Serve the extra UI assets used by the reference-matched homepage."""

    EXTRA_STATIC = {
        '/pixel.css': ('pixel.css', 'text/css'),
        '/reference.css': ('reference.css', 'text/css'),
        '/reference-live.js': ('reference-live.js', 'application/javascript'),
    }

    def handle_request(self):
        url = urlsplit(self.path)
        if self.command == 'GET' and url.path in self.EXTRA_STATIC:
            host = self.headers.get('Host', '')
            if host not in self.server.allowed_hosts:
                return self.respond(403, {'error': 'Unexpected host'})
            origin = self.headers.get('Origin')
            if origin and origin != 'http://' + host:
                return self.respond(403, {'error': 'Cross-origin request denied'})
            name, mime = self.EXTRA_STATIC[url.path]
            return self.respond(200, (Path(__file__).parent / 'ui' / name).read_bytes(), mime)
        return super().handle_request()


class IntegratedApp(App):
    def __init__(self, artifacts, runtime, reader_token, operator_token, policy_key='', allowed_cidrs=(), enforce=False, lab_automation=False):
        super().__init__(artifacts, runtime, reader_token, operator_token, policy_key, allowed_cidrs, enforce, lab_automation)
        self.v15 = V15EvidenceBridge()
        # Replace the default coordinator with the same real policy store but add
        # V15's explicit unknown-forecast authority gate. Existing reviewed Arjuna
        # memory and operator Sudarshana escalation remain available.
        self.response = ResponseCoordinator(
            self.policy,
            lab_automation,
            unknown_auto_approved=self.v15.autonomous_unknown_containment_approved,
        )

    def forecast(self, payload):
        forecast = self.service.predict(payload)
        forecast = self.v15.decorate_forecast(forecast)
        forecast['defence_signal'] = self.response.observe(forecast, payload)
        forecast['automatic_containment'] = forecast['defence_signal'].get('policy', {}).get('status') == 'active'
        forecast['containment_scope'] = 'armed_lab_only; V15 unknown-forecast gate must also approve autonomous containment'
        forecast['krishna_system'] = {
            'garuda_runtime_model': 'v3 graph forecaster',
            'garuda_latest_evidence': 'V15 X-IIoTID temporal branch',
            'arjuna': 'reviewed exact-memory / known-rule path',
            'krishna': 'unknown forecast triage; shadow while V15 containment gate is closed',
            'sudarshana': 'operator-scoped signed containment / breach escalation',
        }
        return forecast

    def integrated_status(self):
        return {
            'runtime_model': self.service.meta,
            'runtime_model_sha256': self.service.model_hash,
            'v15': self.v15.public_status(),
            'response': self.response.status(),
            'enforcement_enabled': self.policy.enforce,
            'audit_integrity': self.policy.verify(),
        }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port', type=int, default=8090)
    p.add_argument('--artifacts', default='garuda_v3/artifacts/residual_run')
    p.add_argument('--runtime', default='garuda_v3/runtime')
    args = p.parse_args()
    runtime = Path(args.runtime); runtime.mkdir(parents=True, exist_ok=True); os.chmod(runtime, 0o700)
    credentials = runtime / 'access.json'
    if not credentials.exists():
        with os.fdopen(os.open(credentials, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as f:
            json.dump(dict(viewer_token=secrets.token_urlsafe(32), operator_token=secrets.token_urlsafe(32)), f)
    access = json.loads(credentials.read_text())
    app = IntegratedApp(
        args.artifacts,
        runtime,
        os.environ.get('GARUDA_READ_TOKEN', access['viewer_token']),
        os.environ.get('GARUDA_OPERATOR_TOKEN', access['operator_token']),
        os.environ.get('GARUDA_POLICY_KEY', ''),
        [c for c in os.environ.get('GARUDA_ALLOWED_CIDRS', '').split(',') if c],
        os.environ.get('GARUDA_ENFORCE') == '1',
        os.environ.get('GARUDA_LAB_AUTOMATION') == '1',
    )
    server = Server(('127.0.0.1', args.port), app)
    server.RequestHandlerClass = IntegratedHandler
    print(f'Krishna Defence + Garuda V15 bridge: http://127.0.0.1:{server.server_port}. Dry-run by default.', flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close(); app.policy.close()


if __name__ == '__main__':
    main()
