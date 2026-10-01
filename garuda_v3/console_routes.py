"""Same-process localhost console bridge. No second listener or browser tokens.

The bridge exposes recorded demonstrations and advisory uploads only. Arbitrary
operator policy endpoints remain on the bearer-authenticated API.
"""
import json
from urllib.parse import parse_qs, urlsplit

from . import legacy_console as legacy
from .main_console import CONSOLE_BUILD, _inject_console
from .upload_inference import analyze

ASSETS = {name: mime for name, mime in (
    ('console-integrated.js', 'application/javascript'),
    ('console-integrated.css', 'text/css'),
    ('console-v131-overlay.js', 'application/javascript'),
    ('console-v131-overlay.css', 'text/css'),
    ('console-v132-extra.js', 'application/javascript'),
    ('console-v132-extra.css', 'text/css'),
)}


def handle_console(handler):
    url = urlsplit(handler.path)
    path = url.path
    console_path = path in ('/', '/console.html', '/index.html', '/health') or path[1:] in ASSETS
    if not console_path and not path.startswith('/bridge/'):
        return False
    app = handler.server.app
    host = handler.headers.get('Host', '')
    origin = handler.headers.get('Origin')
    if host not in handler.server.allowed_hosts or (origin and origin != 'http://' + host):
        handler.respond(403, {'error': 'Local same-origin console only'})
        return True
    if handler.headers.get('Sec-Fetch-Site') == 'cross-site':
        handler.respond(403, {'error': 'Cross-site console request denied'})
        return True
    # A narrow internal adapter, not a bearer-token proxy to arbitrary endpoints.
    def engine(endpoint, method='GET', body=None, operator=False):
        if endpoint == '/api/forecast' and not operator:
            return app.forecast(body)
        if endpoint == '/api/response/approve' and operator:
            return app.response.approve(body['id'], body['attack_type'], body['evidence'])
        raise ValueError('Unsupported internal console operation')

    try:
        if handler.command == 'GET':
            if path in ('/', '/console.html', '/index.html'):
                handler.respond(200, _inject_console(), 'text/html; charset=utf-8')
            elif path[1:] in ASSETS:
                handler.respond(200, (legacy.UI / path[1:]).read_bytes(), ASSETS[path[1:]])
            elif path == '/health':
                handler.respond(200, {'status': 'alive', 'console_build': CONSOLE_BUILD,
                    'surface': 'console.html', 'single_port': True})
            elif path == '/bridge/status':
                handler.respond(200, app.integrated_status())
            elif path == '/bridge/response':
                handler.respond(200, app.response.status())
            elif path == '/bridge/replay':
                if not app.compute.acquire(False):
                    handler.respond(503, {'error': 'Inference busy'})
                    return True
                try:
                    scenario = parse_qs(url.query).get('scenario', ['standard'])[0]
                    names = {'standard': 'replay.json', 'alert': 'alert_replay.json', 'hosts': 'host_replay.json'}
                    payload = json.loads((app.service.folder / names[scenario]).read_text())
                    handler.respond(200, {'graph': payload, 'forecast': app.forecast(payload)})
                finally:
                    app.compute.release()
            else:
                handler.respond(404, {'error': 'Unknown console endpoint'})
            return True
        if handler.command != 'POST':
            handler.respond(405, {'error': 'Method not allowed'})
            return True
        if path not in ('/bridge/analyze', '/bridge/simulate', '/bridge/lab/probe'):
            handler.respond(404, {'error': 'Unknown console endpoint'})
            return True
        values = handler.headers.get_all('Content-Length', [])
        if handler.headers.get('Transfer-Encoding') or len(values) != 1:
            raise ValueError('One bounded Content-Length required')
        length = int(values[0])
        limit = 72 * 1024 * 1024 if path == '/bridge/analyze' else 4096
        if not 0 < length <= limit:
            handler.respond(413, {'error': 'Console request exceeds size limit'})
            return True
        if not app.rate_ok('console'):
            handler.respond(429, {'error': 'Request quota reached; retry after one minute'})
            return True
        if not app.compute.acquire(False):
            handler.respond(503, {'error': 'Inference busy'})
            return True
        try:
            raw = handler.rfile.read(length)
            if len(raw) != length:
                raise ValueError('Incomplete request')
            if path == '/bridge/analyze':
                kind = parse_qs(url.query).get('kind', [''])[0]
                latest = None
                if kind == 'pcap':
                    try:
                        latest = app.latest_state.analyze_pcap(raw)
                    except (ValueError, RuntimeError) as exc:
                        latest = {'status': 'UNAVAILABLE', 'reason': str(exc), 'automatic_containment': False}
                try:
                    result = analyze(raw, kind, app.service.folder)
                except ValueError as exc:
                    if kind != 'pcap': raise
                    result = {'status': 'risk_inference_unavailable', 'windows': 0, 'forecasts': [],
                        'withheld': [{'reason': str(exc)}], 'automatic_containment': False}
                if latest is not None:
                    result['latest_state_forecast'] = latest
            else:
                obj = json.loads(raw)
                if not isinstance(obj, dict):
                    raise ValueError('JSON object required')
                if path == '/bridge/lab/probe':
                    status, result = legacy.LAB.probe(obj.get('ticket'))
                    handler.respond(status, result)
                    return True
                result = legacy._simulate(obj.get('scenario'), engine=engine)
                result['lab'] = legacy.LAB.issue(result['forecast'])
            handler.respond(200, result)
        finally:
            app.compute.release()
    except (ValueError, KeyError, TypeError, UnicodeError) as exc:
        handler.respond(422, {'error': str(exc)})
    except (RuntimeError, OSError):
        handler.respond(503, {'error': 'Console runtime unavailable; no success assumed'})
    return True
