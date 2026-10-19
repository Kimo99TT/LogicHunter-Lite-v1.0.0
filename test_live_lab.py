"""Integration tests use only an ephemeral localhost HTTP server; no external traffic."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import sessions


class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/api/user'):
            import urllib.parse
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            uid = q.get('id', [''])[0]
            users = {'1': {'id': '1', 'name': 'Alice'},
                     '2': {'id': '2', 'name': 'Bob'},
                     '3': {'id': '3', 'name': 'Carol'}}
            value = users.get(uid)
            body = json.dumps(value if value else {'error': 'not found'}).encode()
            self.send_response(200 if value else 404)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/protected':
            cookie = self.headers.get('Cookie', '')
            if 'session=lab-valid-session' in cookie:
                body = b'{"resource":"lab-only","owner":"test-user"}'
                self.send_response(200)
            else:
                body = b'{"error":"forbidden"}'
                self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        body_in = self.rfile.read(length) if length else b''
        body = json.dumps({'received': body_in.decode('utf-8', 'replace')}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def start_lab():
    server = HTTPServer(('127.0.0.1', 0), LabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_live_local_id_variation_is_evidence_not_auto_confirmation():
    server, _thread = start_lab()
    try:
        url = f'http://127.0.0.1:{server.server_port}/api/user?id=1'
        baseline_body = '{"id":"1","name":"Alice"}'
        original = {'url': url, 'method': 'GET', 'headers': {}, 'body': '',
                    'response_preview_length': len(baseline_body)}
        plan = {'vuln_type': 'IDOR', 'action': 'set_param', 'param': 'id',
                'try_values': ['2', '3'], 'confidence': 0.9}
        results = sessions.execute_plan(plan, original,
                                        [f'127.0.0.1:{server.server_port}'],
                                        live=True, rate_limit=0.25)
        baseline = {'status': 200, 'length': len(baseline_body),
                    'body_hash': __import__('hashlib').sha256(baseline_body.encode()).hexdigest()[:16]}
        results = sessions.fill_diffs(results, baseline)
        assert len(results) == 2
        assert all(r['status'] == 200 for r in results)
        assert all(r['diff_vs_baseline'] == 'content_differs_same_status' for r in results)
        verdict, notes = sessions.local_verdict(results, baseline)
        assert verdict == 'ambiguous'
        assert 'ownership' in notes
    finally:
        server.shutdown()
        server.server_close()


def test_live_run_request_budget_is_shared_and_enforced():
    server, _thread = start_lab()
    try:
        original = {'url': f'http://127.0.0.1:{server.server_port}/api/user?id=1',
                    'method': 'GET', 'headers': {}, 'body': '', 'response_preview_length': 30}
        plan = {'vuln_type': 'IDOR', 'action': 'set_param', 'param': 'id',
                'try_values': ['2', '3'], 'confidence': 0.5}
        counter = {'used': 0, 'limit': 1}
        results = sessions.execute_plan(plan, original,
                                        [f'127.0.0.1:{server.server_port}'],
                                        live=True, rate_limit=0.25,
                                        request_budget=1, request_counter=counter)
        assert counter['used'] == 1
        assert results[0]['status'] == 200
        assert results[1]['diff_vs_baseline'] == 'request_budget_exhausted'
    finally:
        server.shutdown()
        server.server_close()


def test_state_changing_methods_blocked_even_when_live():
    server, _thread = start_lab()
    try:
        original = {'url': f'http://127.0.0.1:{server.server_port}/api/user',
                    'method': 'POST', 'headers': {}, 'body': '{"x":1}'}
        plan = {'vuln_type': 'Unclear', 'action': 'remove_cookie', 'param': None,
                'try_values': [], 'confidence': 0.1}
        results = sessions.execute_plan(plan, original,
                                        [f'127.0.0.1:{server.server_port}'], live=True)
        assert results[0]['diff_vs_baseline'] == 'unsafe_method_blocked'
    finally:
        server.shutdown()
        server.server_close()


def test_cookie_protected_local_endpoint_rejects_removed_cookie():
    server, _thread = start_lab()
    try:
        original = {
            'url': f'http://127.0.0.1:{server.server_port}/protected',
            'method': 'GET',
            'headers': {'Cookie': 'session=lab-valid-session'},
            'body': '',
            'response_preview_length': len('{"resource":"lab-only","owner":"test-user"}'),
        }
        plan = {'vuln_type': 'AuthBypass', 'action': 'remove_cookie',
                'param': None, 'try_values': [], 'confidence': 0.7}
        results = sessions.execute_plan(
            plan, original, [f'127.0.0.1:{server.server_port}'], live=True,
            rate_limit=0.25,
        )
        assert len(results) == 1
        assert results[0]['status'] == 403
        baseline = {'status': 200, 'length': original['response_preview_length']}
        results = sessions.fill_diffs(results, baseline)
        verdict, _notes = sessions.local_verdict(results, baseline)
        assert verdict != 'confirmed'
    finally:
        server.shutdown()
        server.server_close()


def test_state_changing_method_requires_two_explicit_opt_ins_and_passes_body(monkeypatch):
    server, _thread = start_lab()
    try:
        monkeypatch.setenv('LH_ALLOW_STATE_CHANGING', '1')
        monkeypatch.setenv('LH_CONFIRM_STATE_CHANGE', 'I_HAVE_AUTHORIZATION')
        original = {
            'url': f'http://127.0.0.1:{server.server_port}/echo',
            'method': 'POST', 'headers': {'Content-Type': 'application/json'},
            'body': '{"lab":"payload"}', 'response_preview_length': 80,
        }
        plan = {'vuln_type': 'Unclear', 'action': 'remove_cookie',
                'param': None, 'try_values': [], 'confidence': 0.1}
        results = sessions.execute_plan(
            plan, original, [f'127.0.0.1:{server.server_port}'], live=True,
            rate_limit=0.25,
        )
        assert results[0]['status'] == 200
        assert 'lab' in results[0]['snippet']
    finally:
        server.shutdown()
        server.server_close()


def test_json_body_param_mutation_supports_nested_graphql_variables(monkeypatch):
    server, _thread = start_lab()
    try:
        monkeypatch.setenv('LH_ALLOW_STATE_CHANGING', '1')
        monkeypatch.setenv('LH_CONFIRM_STATE_CHANGE', 'I_HAVE_AUTHORIZATION')
        original = {
            'url': f'http://127.0.0.1:{server.server_port}/echo',
            'method': 'POST',
            'headers': {'Content-Type': 'application/json'},
            'body': '{"query":"query User($id: ID!) { user(id: $id) { id } }","variables":{"id":1}}',
            'response_preview_length': 120,
        }
        plan = {'vuln_type': 'IDOR', 'action': 'set_body_param',
                'param': 'variables.id', 'try_values': ['2'], 'confidence': 0.5}
        results = sessions.execute_plan(
            plan, original, [f'127.0.0.1:{server.server_port}'], live=True,
            rate_limit=0.25,
        )
        assert results[0]['status'] == 200
        echoed = json.loads(results[0]['snippet'])['received']
        assert json.loads(echoed)['variables']['id'] == 2
    finally:
        server.shutdown()
        server.server_close()
