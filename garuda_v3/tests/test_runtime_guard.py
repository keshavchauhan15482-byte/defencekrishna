import contextlib
import http.client
import io
import json
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from garuda_v3.runtime_guard import framing_error, validate_bind, validate_startup
from garuda_v3.security import PolicyStore
from garuda_v3.server import Handler, Server


class ProbeHandler(Handler):
    def handle_request(self):
        self.respond(200, {'guard_reached': True})


class RuntimeGuardTests(unittest.TestCase):
    def headers(self, **extra):
        headers = Message()
        headers['Host'] = 'localhost'
        for key, value in extra.items():
            headers[key.replace('_', '-')] = value
        return headers

    def test_strict_framing(self):
        for value in ('-1', '+1', '1,1', '1.0', '１２', '9'*100):
            with self.subTest(value=value):
                self.assertIsNotNone(framing_error(self.headers(Content_Length=value), 'POST', 100))
        self.assertIsNone(framing_error(self.headers(Content_Length='2'), 'POST', 100))
        self.assertEqual(framing_error(self.headers(), 'POST', 100)[0], 411)

    def test_ambiguous_headers_and_get_bodies_rejected(self):
        for key in ('Host', 'Content-Length'):
            headers = self.headers(Content_Length='1')
            headers[key] = '1'
            self.assertEqual(framing_error(headers, 'POST', 100)[0], 400)
        self.assertEqual(framing_error(self.headers(Transfer_Encoding='chunked'), 'GET', 100)[0], 400)
        self.assertEqual(framing_error(self.headers(Content_Length='1'), 'GET', 100)[0], 400)

    def test_public_binds_rejected(self):
        for host in ('0.0.0.0', '::', '192.168.1.10', 'example.com'):
            with self.assertRaises(ValueError):
                validate_bind(host)
        for host in ('127.0.0.1', 'localhost', '::1'):
            validate_bind(host)

    def test_enforcement_config_fails_before_side_effects(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'not-created'
            with self.assertRaises(ValueError):
                PolicyStore(target, key='weak', allowed_cidrs=['198.51.100.0/24'], enforce=True)
            self.assertFalse(target.exists())
        with patch.dict(os.environ, {'GARUDA_DEPLOYMENT_PROFILE': 'local'}):
            for key, scope in (('k'*32, ()), ('r'*32, ('198.51.100.0/24',))):
                with self.assertRaises(ValueError):
                    validate_startup('r'*32, 'o'*32, key, scope, True, False)

    def test_pilot_cannot_arm_enforcement_or_lab_automation(self):
        with patch.dict(os.environ, {'GARUDA_DEPLOYMENT_PROFILE': 'pilot'}):
            for enforce, lab in ((True, False), (False, True)):
                with self.assertRaises(ValueError):
                    validate_startup('r'*32, 'o'*32, 'k'*32, ('198.51.100.0/24',), enforce, lab)
            self.assertEqual(validate_startup('r'*32, 'o'*32, '', (), False, False), 'pilot')
        with patch.dict(os.environ, {'GARUDA_DEPLOYMENT_PROFILE': 'typo'}):
            with self.assertRaises(ValueError):
                validate_startup('', '', '', (), False, False)

    def test_policy_expiry_revoke_and_audit_tamper(self):
        with tempfile.TemporaryDirectory() as folder:
            store = PolicyStore(folder, key='k'*40, allowed_cidrs=['198.51.100.0/24'], enforce=True)
            try:
                policy = store.propose('198.51.100.2', 10, 'reviewed lab incident')
                self.assertEqual(len(store.active()), 1)
                with patch('garuda_v3.security.time.time', return_value=10**12):
                    store.publish()
                    self.assertEqual(store.active(), [])
                store.revoke(policy['id'])
                self.assertTrue(store.verify())
                store.db.execute("UPDATE events SET payload='tampered' WHERE id=1")
                store.db.commit()
                self.assertFalse(store.verify())
            finally:
                store.close()
            with self.assertRaises(ValueError):
                PolicyStore(folder)

    def test_threaded_policy_create_and_kill(self):
        with tempfile.TemporaryDirectory() as folder:
            store = PolicyStore(folder, key='k'*40, allowed_cidrs=['198.51.100.0/24'], enforce=True)
            try:
                with ThreadPoolExecutor(max_workers=4) as pool:
                    list(pool.map(lambda i: store.propose('198.51.100.'+str(i), 30, 'parallel reviewed test'), range(1, 13)))
                self.assertEqual(len(store.active()), 12)
                store.kill_switch()
                self.assertEqual(store.active(), [])
                self.assertTrue(store.verify())
                self.assertEqual(json.loads(json.loads((Path(folder)/'policy.json').read_text())['payload'])['policies'], [])
            finally:
                store.close()

    def test_real_http_pilot_guard_covers_console_and_bridge(self):
        app = SimpleNamespace(deployment_profile='pilot', role=lambda token: {'reader': 'viewer', 'operator': 'operator'}.get(token))
        server = Server(('127.0.0.1', 0), app)
        server.RequestHandlerClass = ProbeHandler
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        logs = io.StringIO()
        def request(path, token=None, method='GET'):
            conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
            headers = {'Authorization': 'Bearer '+token} if token else {}
            conn.request(method, path, body=b'{}' if method=='POST' else None, headers=headers)
            response = conn.getresponse()
            result = response.status, response.getheader('X-Request-ID')
            response.read();conn.close()
            return result
        try:
            with contextlib.redirect_stderr(logs):
                for path in ('/console.html', '/bridge/status', '/api/status', '/console-integrated.js'):
                    self.assertEqual(request(path)[0], 401)
                    status, request_id = request(path, 'reader')
                    self.assertEqual(status, 200)
                    self.assertEqual(len(request_id), 24)
                self.assertEqual(request('/bridge/simulate', 'reader', 'POST')[0], 403)
                self.assertEqual(request('/bridge/simulate', 'operator', 'POST')[0], 200)
                self.assertEqual(request('/health')[0], 200)
            self.assertNotIn('Bearer', logs.getvalue())
            self.assertNotIn('/bridge', logs.getvalue())
            self.assertTrue(all(json.loads(line)['event']=='http_request' for line in logs.getvalue().splitlines()))
        finally:
            server.shutdown();server.server_close();thread.join(timeout=3)

    def test_integrated_console_inherits_guard(self):
        from garuda_v3.integrated_server import IntegratedHandler
        self.assertIs(IntegratedHandler.do_GET, Handler.do_GET)
        self.assertIs(IntegratedHandler.do_POST, Handler.do_POST)

    def test_authenticated_readiness_distinguishes_audit_failure(self):
        app = SimpleNamespace(deployment_profile='local', role=lambda token: 'viewer' if token=='reader' else None,
            rate_ok=lambda role: True, policy=SimpleNamespace(verify=lambda: False, folder=Path(tempfile.gettempdir())))
        server = Server(('127.0.0.1', 0), app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for token, expected in ((None, 401), ('reader', 503)):
                conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                headers = {'Authorization': 'Bearer '+token} if token else {}
                conn.request('GET', '/api/readiness', headers=headers)
                response = conn.getresponse()
                self.assertEqual(response.status, expected)
                response.read();conn.close()
            app.policy.verify=lambda: True
            conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
            conn.request('GET', '/api/readiness', headers={'Authorization': 'Bearer reader'})
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())['status'], 'ready')
            conn.close()
        finally:
            server.shutdown();server.server_close();thread.join(timeout=3)
