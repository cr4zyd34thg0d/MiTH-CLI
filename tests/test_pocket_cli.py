#!/usr/bin/env python3
"""
Deterministic Unit & HTTP Streaming Tests for `pocket_cli_server.py`.

Covers:
  (a) Fail-closed 401 on `/api/run`, `/api/cancel`, `/api/clear`, `/api/webhook` without auth
      + strict 127.0.0.1 binding guardrail.
  (b) 6-digit Discord PIN generation, SHA-256 + `hmac.compare_digest` verification,
      3-per-300s rate limiting (HTTP 429), and 5-attempt lockout.
  (c) Secret scrubbing (`DISCORD_BOT_TOKEN`, `mfa.*`, `Bearer ...`, `.env` assignments).
  (d) Stage-0 `prompt_master` enhancement NDJSON event + `stream-json` parsing + 5-gate receipt in `agy` mode.
  (e) `shell` mode live NDJSON streaming + pure & compound `cd` working directory persistence.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

BRIDGE_DIR = Path(__file__).resolve().parent.parent
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import pocket_cli_server as pcs  # noqa: E402

# Use the exact `prompt_master` object the server bound: the real Stage-0 module on the author's
# machine, or the server's built-in pass-through fallback on a fresh fork (where it isn't installed).
prompt_master = pcs.prompt_master
HAS_REAL_PROMPT_MASTER = getattr(prompt_master, "__name__", "") == "prompt_master"


class PocketCLIServerTests(unittest.TestCase):
    """End-to-end HTTP + state tests against an ephemeral `127.0.0.1:0` server."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="pocket_cli_test_")
        self.tmp_dir = Path(self._tmp.name).resolve()

        self.sessions_file = self.tmp_dir / ".pocket_cli_sessions.json"
        self.tunnel_file = self.tmp_dir / ".pocket_cli_tunnel_url"
        self.tunnel_file.write_text("https://demo-pocket.trycloudflare.com\n", encoding="utf-8")

        self.ui_file = self.tmp_dir / "pocket_cli_ui.html"
        self.ui_file.write_text("<!doctype html><title>Pocket CLI UI</title>", encoding="utf-8")

        self.audit_log = self.tmp_dir / "pipeline_audit.jsonl"
        self._audit_patcher = patch.object(prompt_master, "PIPELINE_AUDIT_LOG", self.audit_log, create=True)
        self._audit_patcher.start()

        # Mock executable `agy` script emitting authentic `stream-json` lines
        self.fake_agy = self.tmp_dir / "fake_agy.py"
        self.captured_agy_args = self.tmp_dir / "captured_agy_args.json"
        self.fake_agy.write_text(
            "#!/usr/bin/env python3\n"
            "import json, pathlib, sys\n"
            f"pathlib.Path({str(self.captured_agy_args)!r}).write_text(json.dumps(sys.argv[1:]), encoding='utf-8')\n"
            "events = [\n"
            "  {'event': 'step_update', 'conversation_id': 'conv-pocket-777', 'step_update': {'step_type': 'tool', 'tool_name': 'view_file', 'tool_info': {'parameters': {'Path': '/tmp/demo.py'}}}},\n"
            "  {'event': 'step_update', 'step_update': {'step_type': 'agent_response', 'text_delta': 'Pocket CLI bridge verified cleanly.\\n\\n'}},\n"
            "  {'event': 'step_update', 'step_update': {'step_type': 'agent_response', 'text_delta': '• Zero shell=True sinks active.\\n\\n⭐ **1. Run Tests** — Execute full suite\\n• **2. Inspect Logs** — Check systemd\\n• **3. Clear Session** — Reset state'}},\n"
            "  {'event': 'result', 'result': {'conversation_id': 'conv-pocket-777', 'response': 'Pocket CLI bridge verified cleanly.\\n\\n• Zero shell=True sinks active.\\n\\n⭐ **1. Run Tests** — Execute full suite\\n• **2. Inspect Logs** — Check systemd\\n• **3. Clear Session** — Reset state', 'usage': {'total_tokens': 42}}},\n"
            "]\n"
            "for e in events:\n"
            "    print(json.dumps(e), flush=True)\n",
            encoding="utf-8",
        )
        os.chmod(self.fake_agy, 0o755)

        self.work_root = self.tmp_dir / "work"
        self.work_root.mkdir(parents=True, exist_ok=True)
        (self.work_root / "subdir").mkdir(parents=True, exist_ok=True)
        (self.work_root / "subdir" / "hello.txt").write_text("sub_ok\n", encoding="utf-8")

        self.discord_calls: list[tuple[str, str, dict[str, Any] | None]] = []

        def _fake_discord_api(
            method: str, path: str, payload: dict[str, Any] | None = None
        ) -> dict[str, Any] | list[dict[str, Any]]:
            self.discord_calls.append((method, path, payload))
            if method == "GET" and path.endswith("/channels"):
                return [{"id": "999888777666", "type": 0, "name": "⌨️・iphone-cli"}]
            if method == "POST" and path.endswith("/messages"):
                return {"id": "111222333"}
            return {"id": "999888777666"}

        self._discord_patcher = patch.object(pcs.discord_ctl, "api_request", side_effect=_fake_discord_api)
        self._discord_patcher.start()

        self.state = pcs.PocketCLIState(
            sessions_file=self.sessions_file,
            tunnel_url_file=self.tunnel_file,
            initial_cwd=self.work_root,
            agy_bin_path=str(self.fake_agy),
            owner_pin="7777",
        )
        self.server = pcs.PocketCLIServer(
            ("127.0.0.1", 0),
            pcs.PocketCLIHandler,
            state=self.state,
            ui_html_path=self.ui_file,
        )
        self.port = int(self.server.server_port)
        self._srv_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._srv_thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._srv_thread.join(timeout=2.0)
        self._discord_patcher.stop()
        self._audit_patcher.stop()
        self._tmp.cleanup()

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            req_headers = dict(headers or {})
            payload_bytes: bytes | None = None
            if body is not None:
                payload_bytes = json.dumps(body).encode("utf-8")
                req_headers["Content-Type"] = "application/json"
                req_headers["Content-Length"] = str(len(payload_bytes))
            conn.request(method, path, body=payload_bytes, headers=req_headers)
            resp = conn.getresponse()
            raw = resp.read()
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, resp_headers, raw
        finally:
            conn.close()

    def _authenticate_and_get_token(self) -> str:
        status, _, raw = self._request("POST", "/api/auth/request-code", {})
        self.assertEqual(status, 200, raw.decode())
        # Extract 6-digit PIN from mocked Discord call
        last_payload = self.discord_calls[-1][2]
        assert isinstance(last_payload, dict)
        m = re.search(r"\*\*`(\d{6})`\*\*", str(last_payload.get("content", "")))
        self.assertIsNotNone(m)
        assert m is not None
        pin = m.group(1)

        v_status, v_headers, v_raw = self._request(
            "POST",
            "/api/auth/verify-code",
            {"code": pin},
            headers={"X-Forwarded-Proto": "https"},
        )
        self.assertEqual(v_status, 200)
        self.assertIn("secure", v_headers.get("set-cookie", "").lower())
        self.assertIn("httponly", v_headers.get("set-cookie", "").lower())
        data = json.loads(v_raw.decode("utf-8"))
        return str(data["session_token"])

    # --- (a) Fail-closed 401 & 127.0.0.1 Binding Guardrails ---
    def test_a_fail_closed_401_and_pwa_endpoints(self) -> None:
        with self.assertRaises(ValueError):
            pcs.PocketCLIServer(("0.0.0.0", 0), pcs.PocketCLIHandler, state=self.state)

        for ep in ("/api/run", "/api/cancel", "/api/clear", "/api/webhook"):
            status, _, raw = self._request("POST", ep, {"input": "whoami"})
            self.assertEqual(status, 401, f"Expected 401 on {ep}, got {status}: {raw!r}")

        status, _, raw = self._request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["service"], "agy-pocket-cli")

        status, hdrs, raw = self._request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("no-store", hdrs.get("cache-control", ""))
        self.assertIn(b"Pocket CLI UI", raw)

        status, _, raw = self._request("GET", "/manifest.json")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["short_name"], "MiTH CLI")

        status, _, _ = self._request("GET", "/cli")
        self.assertEqual(status, 200)

        status, _, _ = self._request("POST", "/api/run", {"input": "ls"}, headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)

        status, _, raw = self._request("GET", "/icon.svg")
        self.assertEqual(status, 200)
        self.assertIn(b"#0A84FF", raw)

        status, _, raw = self._request("GET", "/api/auth/status")
        self.assertEqual(status, 200)
        st_data = json.loads(raw)
        self.assertFalse(st_data["authenticated"])
        self.assertEqual(st_data["tunnel_url"], "https://demo-pocket.trycloudflare.com")
        self.assertEqual(st_data["discord_channel"], "#⌨️・cli")

    # --- (b) PIN Generation, HMAC Verification, Lockout & Rate Limiting ---
    def test_b_pin_auth_hmac_and_rate_limiting(self) -> None:
        tok = self._authenticate_and_get_token()
        self.assertTrue(self.state.verify_session_token(tok))
        self.assertFalse(self.state.verify_session_token(tok + "tampered"))

        # Check 0600 permissions on session store
        mode = stat.S_IMODE(self.sessions_file.stat().st_mode)
        self.assertEqual(mode, 0o600)

        # Verify Cookie auth works as well as Bearer auth
        status, _, raw = self._request(
            "GET",
            "/api/auth/status",
            headers={"Cookie": f"agy_pocket_session={tok}"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(raw)["authenticated"])

        # Request 2nd and 3rd PINs -> allowed; 4th within 300s -> HTTP 429
        s2, _, _ = self._request("POST", "/api/auth/request-code", {})
        s3, _, _ = self._request("POST", "/api/auth/request-code", {})
        s4, _, raw4 = self._request("POST", "/api/auth/request-code", {})
        self.assertEqual(s2, 200)
        self.assertEqual(s3, 200)
        self.assertEqual(s4, 429, raw4.decode())

        # Verify 5 wrong attempts invalidate active PIN even if correct PIN is submitted 6th
        last_msg = str((self.discord_calls[-1][2] or {}).get("content", ""))
        m = re.search(r"\*\*`(\d{6})`\*\*", last_msg)
        assert m is not None
        active_pin = m.group(1)
        for _ in range(5):
            bad_s, _, _ = self._request("POST", "/api/auth/verify-code", {"code": "000000"})
            self.assertEqual(bad_s, 401)

        sixth_s, _, _ = self._request("POST", "/api/auth/verify-code", {"code": active_pin})
        self.assertEqual(sixth_s, 401)

    # --- (c) Secret Scrubbing ---
    def test_c_secret_scrubbing(self) -> None:
        dyn_bot_secret = "bot_tok_val_" + ("Z9x8" * 6)
        dyn_mfa = "mfa." + ("aB3_" * 7)
        dyn_bearer = "Bearer " + ("eyJhbGciOi" * 3)
        dyn_jwt = "M" + ("T" * 23) + "." + ("X" * 6) + "." + ("y" * 27)

        with patch.dict(os.environ, {"DISCORD_BOT_TOKEN": dyn_bot_secret}, clear=False):
            sample = (
                f"Loaded token={dyn_bot_secret}\n"
                f"MFA={dyn_mfa}\n"
                f"Auth: {dyn_bearer}\n"
                f"RawJWT: {dyn_jwt}\n"
                "DISCORD_BOT_TOKEN=super_secret_inline_value\n"
            )
            cleaned = pcs.scrub_secrets(sample)

        self.assertNotIn(dyn_bot_secret, cleaned)
        self.assertNotIn(dyn_mfa, cleaned)
        self.assertNotIn("eyJhbGciOi", cleaned)
        self.assertNotIn(dyn_jwt, cleaned)
        self.assertNotIn("super_secret_inline_value", cleaned)
        self.assertIn("[REDACTED", cleaned)

    # --- (d) Stage-0 `prompt_master` Enhancement Event in `agy` Mode ---
    @unittest.skipUnless(
        HAS_REAL_PROMPT_MASTER,
        "Optional Stage-0 `prompt_master` module not installed (forks use the built-in pass-through)",
    )
    def test_d_stage0_enhancement_and_agy_streaming(self) -> None:
        tok = self._authenticate_and_get_token()
        status, hdrs, raw = self._request(
            "POST",
            "/api/run",
            {
                "input": "build a secure python endpoint for dj mith",
                "mode": "agy",
                "enhance": True,
                "sync_discord": False,
                "model": "argon-high",
            },
            headers={"Authorization": f"Bearer {tok}"},
        )
        self.assertEqual(status, 200)
        self.assertIn("application/x-ndjson", hdrs.get("content-type", ""))

        events = [json.loads(ln) for ln in raw.decode("utf-8").splitlines() if ln.strip()]
        self.assertGreaterEqual(len(events), 4)

        ev0 = events[0]
        self.assertEqual(ev0["type"], "enhanced")
        self.assertTrue(ev0["enhanced_active"])
        self.assertEqual(ev0["model"], "gemini-4-argon-high")
        self.assertEqual(ev0["effort"], "high")
        # Mobile normalizer enforces 'MiTH' over 'dj mith'
        self.assertIn("MiTH", ev0["clarified_intent"])
        self.assertTrue(bool(ev0["agent_id"]))

        tool_events = [e for e in events if e["type"] == "tool"]
        chunk_events = [e for e in events if e["type"] == "chunk"]
        self.assertTrue(any("view_file (demo.py)" in e["name"] for e in tool_events))
        self.assertGreaterEqual(len(chunk_events), 2)

        done_ev = events[-1]
        self.assertEqual(done_ev["type"], "done")
        self.assertEqual(done_ev["mode"], "agy")
        self.assertEqual(done_ev["conversation_id"], "conv-pocket-777")
        self.assertTrue(done_ev["receipt"]["gates"]["G1_prompt_enhanced"])
        self.assertEqual(done_ev["receipt"]["passed_count"], 5)

        # Verify `agy` binary received `<flash_mastered_prompt>` via `--print`
        passed_argv = json.loads(self.captured_agy_args.read_text(encoding="utf-8"))
        print_idx = passed_argv.index("--print")
        self.assertIn("<flash_mastered_prompt>", passed_argv[print_idx + 1])

        # Verify `/api/webhook` wrapper & `/api/clear`
        wh_status, _, wh_raw = self._request(
            "POST",
            "/api/webhook",
            {"input": "check status", "mode": "agy", "enhance": True},
            headers={"Authorization": f"Bearer {tok}"},
        )
        self.assertEqual(wh_status, 200)
        wh_data = json.loads(wh_raw.decode("utf-8"))
        self.assertTrue(wh_data["ok"])
        self.assertIn("Pocket CLI bridge verified", wh_data["output"])

        clr_status, _, _ = self._request(
            "POST", "/api/clear", {}, headers={"Authorization": f"Bearer {tok}"}
        )
        self.assertEqual(clr_status, 200)
        self.assertEqual(self.state.current_conv_id, "")

    # --- (e) `shell` Mode Streaming & `cd` CWD Persistence ---
    def test_e_shell_streaming_and_cd_persistence(self) -> None:
        tok = self._authenticate_and_get_token()

        # 1. Pure `cd subdir` updates persistent CWD
        s1, _, raw1 = self._request(
            "POST",
            "/api/run",
            {"input": "cd subdir", "mode": "shell", "sync_discord": False},
            headers={"Authorization": f"Bearer {tok}"},
        )
        self.assertEqual(s1, 200)
        ev1 = [json.loads(ln) for ln in raw1.decode("utf-8").splitlines() if ln.strip()]
        self.assertEqual(ev1[0]["type"], "shell_start")
        self.assertEqual(ev1[-1]["type"], "done")
        self.assertEqual(ev1[-1]["exit_code"], 0)
        expected_sub = str((self.work_root / "subdir").resolve())
        self.assertEqual(ev1[-1]["cwd"], expected_sub)

        # 2. Next shell command runs inside persisted `subdir` using `$ ` shortcut even if mode="agy"
        s2, _, raw2 = self._request(
            "POST",
            "/api/run",
            {"input": "$ cat hello.txt && cd ..", "mode": "agy", "sync_discord": False},
            headers={"Authorization": f"Bearer {tok}"},
        )
        self.assertEqual(s2, 200)
        ev2 = [json.loads(ln) for ln in raw2.decode("utf-8").splitlines() if ln.strip()]
        stdout_lines = [e["line"] for e in ev2 if e["type"] == "stdout"]
        self.assertIn("sub_ok", stdout_lines)
        # Compound `&& cd ..` also persisted back to `self.work_root` via PWD sentinel!
        self.assertEqual(ev2[-1]["cwd"], str(self.work_root.resolve()))

    # --- (f) Direct AGY Mode (Enhance Default OFF) & Zero-Discord Authentication ---
    def test_f_direct_agy_and_zero_discord_auth(self) -> None:
        # 1. Direct 1-tap connect via /api/auth/direct on localhost / Tailscale
        status_dir, hdrs_dir, raw_dir = self._request("POST", "/api/auth/direct", {})
        self.assertEqual(status_dir, 200)
        data_dir = json.loads(raw_dir.decode("utf-8"))
        self.assertTrue(data_dir.get("ok"))
        tok_dir = data_dir.get("session_token")
        self.assertTrue(bool(tok_dir))
        self.assertTrue(any(k.lower() == "set-cookie" for k in hdrs_dir))

        # 2. Direct owner PIN verify without needing any Discord PIN request
        status_pin, _, raw_pin = self._request("POST", "/api/auth/verify-code", {"code": "7777"})
        self.assertEqual(status_pin, 200)
        data_pin = json.loads(raw_pin.decode("utf-8"))
        self.assertTrue(data_pin.get("ok"))
        tok_pin = data_pin.get("session_token")
        self.assertTrue(bool(tok_pin))

        # 3. Direct AGY run: omit 'enhance' flag -> defaults to False (pure raw prompt)
        status_run, _, raw_run = self._request(
            "POST",
            "/api/run",
            {
                "input": "write a python function to compute fibonacci",
                "mode": "agy",
                # Note: 'enhance' omitted -> must default to False
                "sync_discord": False,
            },
            headers={"Authorization": f"Bearer {tok_pin}"},
        )
        self.assertEqual(status_run, 200)
        events = [json.loads(ln) for ln in raw_run.decode("utf-8").splitlines() if ln.strip()]
        self.assertGreaterEqual(len(events), 2)
        ev0 = events[0]
        self.assertEqual(ev0["type"], "enhanced")
        self.assertFalse(ev0["enhanced_active"])

        # Check captured argv passed to `fake_agy`: raw input should NOT contain <flash_mastered_prompt>
        passed_argv = json.loads(self.captured_agy_args.read_text(encoding="utf-8"))
        print_idx = passed_argv.index("--print")
        raw_passed_prompt = passed_argv[print_idx + 1]
        self.assertEqual(raw_passed_prompt, "write a python function to compute fibonacci")
        self.assertNotIn("<flash_mastered_prompt>", raw_passed_prompt)


if __name__ == "__main__":
    unittest.main()
