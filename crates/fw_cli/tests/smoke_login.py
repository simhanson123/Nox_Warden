#!/usr/bin/env python3
"""Local CLI protocol smoke; synthetic credentials stay in temporary private files."""
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import uuid

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "target/debug/fw_cli"
TOKEN = uuid.uuid4().hex + uuid.uuid4().hex
COOKIE = uuid.uuid4().hex + uuid.uuid4().hex
CSRF = uuid.uuid4().hex + uuid.uuid4().hex
requests = []
used = False
redirect = False


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, body, extra=None):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        global used
        requests.append(("POST", self.path))
        assert self.path == "/api/v1/session/bootstrap"
        assert self.headers["Origin"] == base
        assert self.headers["Content-Type"].split(";")[0] == "application/json"
        uuid.UUID(self.headers["Idempotency-Key"])
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert body == {"token": TOKEN}
        if redirect:
            self.reply(302, {}, {"Location": base + "/must-not-follow"})
        elif used:
            self.reply(401, {"code": "UNAUTHENTICATED"})
        else:
            used = True
            self.reply(200, {"data": {"authenticated": True, "csrf_token": CSRF}},
                       {"Set-Cookie": f"fw_session={COOKIE}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"})

    def do_GET(self):
        requests.append(("GET", self.path))
        if self.path == "/api/v1/auth/status":
            self.reply(200, {"data": {"owner_enrolled": False}})
            return
        assert self.headers["Cookie"] == "fw_session=" + COOKIE
        assert self.headers["X-CSRF-Token"] == CSRF
        assert self.path in ("/api/v1/status", "/api/v1/assets", "/api/v1/services")
        self.reply(200, {"data": {"mode": "observe", "enforcement": False}} if self.path.endswith("status") else {"data": []})


server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
base = f"http://127.0.0.1:{server.server_port}"
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
checks = []
try:
    with tempfile.TemporaryDirectory(prefix="fw-cli-smoke-") as tmp:
        directory = Path(tmp)
        token = directory / "bootstrap-token"
        token.write_text(TOKEN)
        token.chmod(0o600)
        session = directory / "session.json"
        env = dict(os.environ, FW_API_URL=base, FW_BOOTSTRAP_FILE=str(token), FW_SESSION_FILE=str(session))

        def call(command, expected=0, settings=None):
            result = subprocess.run([str(BINARY), command], env=settings or env, text=True, capture_output=True, timeout=15)
            assert result.returncode == expected, (command, result.returncode, result.stderr)
            assert all(value not in result.stdout + result.stderr for value in (TOKEN, COOKIE, CSRF)), "credential printed"
            return json.loads(result.stdout) if result.stdout else None

        result = call("login")
        assert result["authenticated"] is True
        stored = json.loads(session.read_text())
        assert stored["api_origin"] == base and stored["csrf_token"] == CSRF
        assert session.stat().st_mode & 0o777 == 0o600
        checks.append("one-use file bootstrap produces private origin-bound session without logging credentials")
        assert call("status")["data"]["enforcement"] is False
        assert call("assets")["data"] == [] and call("services")["data"] == []
        checks.append("authenticated status and catalogue reads send stored session")
        call("login", expected=1)
        checks.append("consumed bootstrap rejected")
        count = len(requests)
        call("status", expected=1, settings=dict(env, FW_API_URL="http://127.0.0.1:1"))
        assert len(requests) == count
        checks.append("session origin mismatch rejected before network")
        redirect = True
        session.unlink()
        count = len(requests)
        call("login", expected=1)
        assert len(requests) == count + 2 and not session.exists()
        checks.append("bootstrap redirect refused without persisting credentials")
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
print(json.dumps({"status": "PASS", "checks": checks, "count": len(checks), "real_controller": False, "synthetic_credentials": True}, indent=2))
