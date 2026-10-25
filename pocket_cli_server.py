#!/usr/bin/env python3
"""
Antigravity Pocket CLI Server (`pocket_cli_server.py`)

Minimalist, OWASP-hardened localhost HTTP/NDJSON streaming bridge for iPhone Pocket CLI:
  - Strictly bound to 127.0.0.1 (never 0.0.0.0); exposed externally only via HTTPS tunnel.
  - 1-Tap 6-digit Discord Pairing PIN -> SHA-256 + hmac.compare_digest 90-day session cookie/Bearer token.
  - Stage-0 `prompt_master.py` automatic enhancement (`enhance=True` default) + 5-Gate receipt validation.
  - Live `stream-json` streaming from `agy` (`shell=False`, explicit timeouts).
  - Live WSL bash streaming (`mode="shell"`, `shell=False`) with persistent `cd` CWD tracking.
  - Automatic secret scrubbing before any HTTP chunk or Discord `#⌨️・iphone-cli` sync embed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.cookies
import importlib.util
import json
import logging
import os
import queue
import re
import secrets
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

BRIDGE_DIR = Path(__file__).resolve().parent
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

try:
    from dotenv import load_dotenv

    load_dotenv(BRIDGE_DIR / ".env")
except ImportError:
    _env_file = BRIDGE_DIR / ".env"
    if _env_file.exists():
        for _raw_ln in _env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            _ln = _raw_ln.strip()
            if _ln and not _ln.startswith("#") and "=" in _ln:
                _k, _v = _ln.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip().strip("'\""))

try:
    import discord_ctl  # type: ignore
except ImportError:
    class _DiscordCtlFallback:
        @staticmethod
        def api_request(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("Optional discord_ctl bridge is not configured.")

    discord_ctl = _DiscordCtlFallback()  # type: ignore

try:
    import prompt_master  # type: ignore
except ImportError:
    class _PromptMasterFallback:
        @staticmethod
        def normalize_mobile_text(txt: str) -> str:
            return txt.strip()

        @staticmethod
        def select_specialized_agent(*_args: Any, **_kwargs: Any) -> tuple[str, dict[str, Any]]:
            return "default-cli", {}

        @staticmethod
        def get_agent_hierarchy_info(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            return {"role": "agent", "tier": "primary", "pod": "default"}

        @staticmethod
        def master_user_prompt(raw_prompt: str, **_kwargs: Any) -> str:
            return raw_prompt

        @staticmethod
        def validate_turn_output(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            return {"all_passed": True, "footer_stamp": "⚡ MiTH CLI"}

    prompt_master = _PromptMasterFallback()  # type: ignore

import model_failover  # noqa: E402  (shared quota-aware model failover with bot.py)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pocket-cli-server")

# --- Strict Security & Runtime Constants ---
BIND_HOST: str = "127.0.0.1"
PORT: int = int(os.getenv("POCKET_CLI_PORT", "8788"))
WORKSPACE_DIR: Path = Path(
    os.getenv("AGY_WORKSPACE_DIR", str(BRIDGE_DIR / "workspace")).strip()
)
UI_HTML_PATH: Path = BRIDGE_DIR / "pocket_cli_ui.html"
BUDGET_HTML_PATH: Path = BRIDGE_DIR / "workspace" / "outputs" / "budget-tool.html"
# The budget app is a React/Babel single file loaded from cdnjs, so /budget (auth-gated) needs a
# narrowly relaxed CSP. Every other route keeps the strict default policy.
BUDGET_PORT: int = int(os.getenv("POCKET_BUDGET_PORT", "8789"))
BUDGET_ICON_180_PATH: Path = BRIDGE_DIR / "workspace" / "outputs" / "budget-icon-180.png"
BUDGET_ICON_512_PATH: Path = BRIDGE_DIR / "workspace" / "outputs" / "budget-icon-512.png"
BUDGET_MANIFEST: dict[str, Any] = {
    "name": "Budget",
    "short_name": "Budget",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "background_color": "#090d14",
    "theme_color": "#090d14",
    "icons": [
        {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
        {"src": "/apple-touch-icon.png", "sizes": "180x180", "type": "image/png"},
    ],
}
BUDGET_HEAD_INJECT = (
    '<link rel="manifest" href="/manifest.json">'
    '<link rel="apple-touch-icon" href="/apple-touch-icon.png">'
    '<meta name="apple-mobile-web-app-capable" content="yes">'
    '<meta name="apple-mobile-web-app-title" content="Budget">'
    '<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">'
)
BUDGET_LOGIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<link rel="manifest" href="/manifest.json"><link rel="apple-touch-icon" href="/apple-touch-icon.png">
<meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-title" content="Budget">
<title>Budget</title><style>
body{background:#090d14;color:#f1f5f9;font-family:system-ui,-apple-system,sans-serif;margin:0;padding:48px 24px;max-width:420px;margin:auto}
h1{font-size:22px;margin:0 0 6px}p{color:#94a3b8;font-size:14px;margin:0 0 20px}
button,input{width:100%;box-sizing:border-box;font-size:17px;border-radius:10px;padding:14px;margin-bottom:12px;font-family:inherit}
button{background:#6366f1;border:0;color:#fff;font-weight:600}input{background:#0b1220;border:1px solid #1f293d;color:#f1f5f9;letter-spacing:6px;text-align:center}
#m{font-size:13px;color:#f59e0b;min-height:18px}</style></head><body>
<h1>Budget</h1><p>Private. Get a 6-digit code sent to your Discord, then enter it.</p>
<button id="r">Send code to Discord</button>
<input id="c" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="------">
<button id="v">Unlock</button><div id="m"></div>
<script>
var m=document.getElementById('m');
function post(u,b){return fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{}),credentials:'same-origin'}).then(function(r){return r.json().then(function(j){j._s=r.status;return j;});});}
document.getElementById('r').onclick=function(){m.textContent='Sending...';post('/api/auth/request-code').then(function(j){m.textContent=j.ok?'Code sent. Check Discord.':(j.error||'Failed');}).catch(function(){m.textContent='Network error';});};
document.getElementById('v').onclick=function(){post('/api/auth/verify-code',{code:document.getElementById('c').value.trim()}).then(function(j){if(j.ok){location.replace('/');}else{m.textContent=j.error||'Wrong code';}}).catch(function(){m.textContent='Network error';});};
</script></body></html>"""
BUDGET_ONLY_GET = frozenset({"/", "/budget", "/manifest.json", "/icon-512.png", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"})
BUDGET_ONLY_POST = frozenset({"/api/auth/request-code", "/api/auth/verify-code"})

BUDGET_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'"
)
SESSIONS_FILE: Path = WORKSPACE_DIR / ".pocket_cli_sessions.json"
TUNNEL_URL_FILE: Path = WORKSPACE_DIR / ".pocket_cli_tunnel_url"

AGY_BIN_PATH: str = os.getenv("AGY_BIN_PATH", "agy").strip()
DEFAULT_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-4-argon-high").strip()
DEFAULT_EFFORT: str = os.getenv("AGY_EFFORT", "medium").strip()

DISCORD_GUILD_ID: str = (
    os.getenv("DISCORD_GUILD_ID", "").strip() or ""
)
OWNER_USER_ID: str = (
    os.getenv("OWNER_USER_ID", "").strip() or ""
)
IPHONE_CLI_CATEGORY_ID: str = ""
IPHONE_CLI_CHANNEL_DISPLAY: str = "#⌨️・cli"
IPHONE_CLI_CHANNEL_NAME: str = "⌨️・cli"

DEFAULT_ENHANCE: bool = os.getenv("POCKET_CLI_DEFAULT_ENHANCE", "0").strip().lower() in ("1", "true", "yes")
OWNER_PIN: str = os.getenv("POCKET_CLI_PIN", "").strip()

PIN_TTL_SECONDS: int = 300
PIN_RATE_WINDOW_SECONDS: int = 300
PIN_MAX_REQUESTS_PER_WINDOW: int = 3
PIN_MAX_VERIFY_ATTEMPTS: int = 5
SESSION_TTL_SECONDS: int = 90 * 24 * 3600  # 90 days (7,776,000s)

MAX_HTTP_BODY_BYTES: int = 65536
MAX_UPLOAD_BODY_BYTES: int = 25 * 1024 * 1024  # 25 MB for iPhone photo & file uploads
UPLOADS_DIR: Path = WORKSPACE_DIR / "uploads"
EPHEMERAL_UPLOADS_DIR: Path = UPLOADS_DIR / ".ephemeral"
DOCUMENTS_UPLOADS_DIR: Path = Path("./workspace/uploads/iphone")
MAX_INPUT_CHARS: int = 16000
AGY_TIMEOUT_SECONDS: float = float(os.getenv("AGY_TIMEOUT_SECONDS", "1800.0"))
AGY_MAX_TRANSCRIPT_BYTES: int = 1_200_000  # Allow deep 30-min sessions before rotating
SHELL_TIMEOUT_SECONDS: float = 300.0
MAX_SHELL_STREAM_LINES: int = 400
DISCORD_OUTPUT_MAX_CHARS: int = 1500

ICON_512_PATH: Path = BRIDGE_DIR / "mith_cli_icon.png"
ICON_180_PATH: Path = BRIDGE_DIR / "mith_cli_icon_180.png"
CLI_APP_DATA_DIR: Path = Path.home() / ".gemini" / "antigravity-cli"
WIN_APP_DATA_DIR: Path = Path("~/.gemini/antigravity")

AGY_EXTRA_DIRS: tuple[str, ...] = (
    "~/Music",
    "~/Documents",
)

AUDIO_EXT_MIME: dict[str, str] = {
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".flac": "audio/flac",
    ".ogg": "audio/ogg",
    ".m4a": "audio/mp4",
    ".aac": "audio/aac",
}

ALLOWED_AUDIO_ROOTS: tuple[Path, ...] = (
    Path("~/Music"),
    Path("~/Documents"),
    BRIDGE_DIR,
    Path("/tmp"),
)

SENSITIVE_ENV_KEY_RE = re.compile(
    r"(?:TOKEN|SECRET|API_KEY|PRIVATE_KEY|PASSWORD|PASSWD|AUTH_KEY|CLIENT_SECRET|WEBHOOK)",
    re.IGNORECASE,
)
MFA_TOKEN_RE = re.compile(r"\bmfa\.[A-Za-z0-9_\-]{12,}")
DISCORD_BOT_JWT_RE = re.compile(r"\b[MN][A-Za-z\d]{22,}\.[\w\-]{5,}\.[\w\-]{20,}")
BEARER_HEADER_RE = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._\-~+/]{8,}=*")
COMMON_API_KEY_RE = re.compile(
    r"\b(?:AIza[0-9A-Za-z\-_]{20,}|ghp_[0-9A-Za-z]{20,}|sk-[A-Za-z0-9\-_]{20,})"
)
ENV_ASSIGNMENT_SECRET_RE = re.compile(
    r"(?im)\b([A-Z0-9_]*(?:TOKEN|SECRET|API_KEY|PRIVATE_KEY|PASSWORD|PASSWD|CLIENT_SECRET|WEBHOOK_URL)[A-Z0-9_]*)\s*=\s*(['\"]?)[^\s'\"\r\n]+\2"
)

ICON_SVG: str = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <rect width="512" height="512" rx="112" fill="#06080D"/>
  <!-- Modern Geometric Architectural M >_ Emblem -->
  <g fill="none" stroke="#0A84FF" stroke-width="32" stroke-linecap="square" stroke-linejoin="miter">
    <path d="M116 350 V162 L200 294 L284 162 V350"/>
    <path d="M322 208 L368 254 L322 300"/>
    <path d="M322 334 H396"/>
  </g>
</svg>
"""

PWA_MANIFEST: dict[str, Any] = {
    "name": "MiTH CLI",
    "short_name": "MiTH CLI",
    "start_url": "/cli",
    "display": "standalone",
    "background_color": "#06080D",
    "theme_color": "#06080D",
    "icons": [
        {"src": "/icon-512.png?v=10", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
        {"src": "/apple-touch-icon.png?v=10", "sizes": "180x180", "type": "image/png"},
        {"src": "/icon.svg?v=10", "sizes": "any", "type": "image/svg+xml"},
    ],
}

SW_JS: str = """// MiTH CLI Native iOS & Web Push Service Worker
self.addEventListener('install', function (e) {
  self.skipWaiting();
});

self.addEventListener('activate', function (e) {
  e.waitUntil(self.clients.claim());
});

self.addEventListener('push', function (e) {
  var payload = {};
  try {
    payload = e.data ? e.data.json() : {};
  } catch (_) {
    payload = { title: 'MiTH CLI', body: e.data ? e.data.text() : 'Turn complete' };
  }
  var title = payload.title || 'MiTH CLI • Turn Complete';
  var options = {
    body: payload.body || 'Your command has finished.',
    icon: '/apple-touch-icon.png?v=10',
    badge: '/apple-touch-icon.png?v=10',
    tag: payload.tag || ('turn-' + Date.now()),
    renotify: true,
    data: {
      url: payload.url || '/cli'
    }
  };
  e.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', function (e) {
  e.notification.close();
  var targetUrl = (e.notification.data && e.notification.data.url) || '/cli';
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (clients) {
      for (var i = 0; i < clients.length; i++) {
        var client = clients[i];
        if ('focus' in client) {
          return client.focus();
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl);
      }
    })
  );
});
"""


def _collect_known_secret_values() -> list[str]:
    """Collect active secret values from environment and `.env` for exact-match redaction."""
    values: set[str] = set()
    bot_tok = os.getenv("DISCORD_BOT_TOKEN", "").strip()
    if len(bot_tok) >= 8:
        values.add(bot_tok)

    for k, v in os.environ.items():
        if SENSITIVE_ENV_KEY_RE.search(k):
            cleaned = v.strip().strip("'\"")
            if len(cleaned) >= 8:
                values.add(cleaned)

    env_path = BRIDGE_DIR / ".env"
    if env_path.exists():
        try:
            for raw_ln in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                ln = raw_ln.strip()
                if not ln or ln.startswith("#") or "=" not in ln:
                    continue
                k, v = ln.split("=", 1)
                if SENSITIVE_ENV_KEY_RE.search(k.strip()):
                    cleaned = v.strip().strip("'\"")
                    if len(cleaned) >= 8:
                        values.add(cleaned)
        except OSError:
            pass

    # Replace longest secrets first so partial substrings never leak tails
    return sorted(values, key=len, reverse=True)


def scrub_secrets(text: str) -> str:
    """Redact `.env` secrets, Discord tokens, `mfa.*`, and `Bearer` credentials from output."""
    if not text:
        return ""
    scrubbed = str(text)
    for secret_val in _collect_known_secret_values():
        if secret_val in scrubbed:
            scrubbed = scrubbed.replace(secret_val, "[REDACTED_SECRET]")

    scrubbed = ENV_ASSIGNMENT_SECRET_RE.sub(r"\1=[REDACTED]", scrubbed)
    scrubbed = MFA_TOKEN_RE.sub("[REDACTED_MFA_TOKEN]", scrubbed)
    scrubbed = DISCORD_BOT_JWT_RE.sub("[REDACTED_DISCORD_TOKEN]", scrubbed)
    scrubbed = BEARER_HEADER_RE.sub(r"\1[REDACTED_TOKEN]", scrubbed)
    scrubbed = COMMON_API_KEY_RE.sub("[REDACTED_API_KEY]", scrubbed)
    return scrubbed


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def extract_session_token(headers: Mapping[str, str] | Any) -> str | None:
    """
    Extract session token checking `Authorization: Bearer <tok>` first,
    then falling back to `Cookie: agy_pocket_session=<tok>`.
    """
    if headers is None:
        return None

    auth_val = headers.get("Authorization") or headers.get("authorization") or ""
    if isinstance(auth_val, str) and auth_val.strip():
        parts = auth_val.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            tok = parts[1].strip()
            if tok:
                return tok

    cookie_val = headers.get("Cookie") or headers.get("cookie") or ""
    if isinstance(cookie_val, str) and cookie_val.strip():
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(cookie_val)
            morsel = jar.get("agy_pocket_session")
            if morsel and morsel.value.strip():
                return morsel.value.strip()
        except http.cookies.CookieError:
            pass
        for part in cookie_val.split(";"):
            item = part.strip()
            if item.startswith("agy_pocket_session="):
                cand = item.split("=", 1)[1].strip().strip('"')
                if cand:
                    return cand

    return None


def read_tunnel_url(tunnel_file: Path | None = None) -> str:
    """Read active public HTTPS tunnel URL from `WORKSPACE_DIR / '.pocket_cli_tunnel_url'`."""
    path = tunnel_file or TUNNEL_URL_FILE
    try:
        if path.exists():
            return path.read_text(encoding="utf-8-sig", errors="ignore").strip()
    except OSError:
        pass
    return ""


def resolve_compatible_effort(model: str, preferred_effort: str = DEFAULT_EFFORT) -> str:
    """Ensure `--model` suffix and `--effort` flag stay aligned for `agy`."""
    m = (model or "").lower().strip()
    if "flash" in m and "-high" in m:
        return "high"
    for suffix in ("low", "medium", "high", "xhigh", "max"):
        if m.endswith(f"-{suffix}"):
            return suffix
    if preferred_effort.lower() in ("low", "medium", "high", "xhigh", "max"):
        return preferred_effort.lower()
    return "medium"


def resolve_model_and_effort(prompt_text: str, requested_model: str = "auto") -> tuple[str, str]:
    """Resolve UI model selector (`auto`, `flash`, `argon-high`, etc.) into `(cli_model, effort)`."""
    req = (requested_model or "auto").strip().lower()
    shorthand_map: dict[str, tuple[str, str]] = {
        "flash": ("gemini-3.8-flash-high", "high"),
        "flash-high": ("gemini-3.8-flash-high", "high"),
        "gemini-3.8-flash-high": ("gemini-3.8-flash-high", "high"),
        "argon": ("gemini-4-argon-medium", "medium"),
        "argon-medium": ("gemini-4-argon-medium", "medium"),
        "gemini-4-argon-medium": ("gemini-4-argon-medium", "medium"),
        "argon-high": ("gemini-4-argon-high", "high"),
        "gemini-4-argon-high": ("gemini-4-argon-high", "high"),
        "argon-low": ("gemini-4-argon-low", "low"),
        "gemini-4-argon-low": ("gemini-4-argon-low", "low"),
        "opus": ("claude-opus-5-5-high", "high"),
        "opus-high": ("claude-opus-5-5-high", "high"),
        "claude-opus-5-5-high": ("claude-opus-5-5-high", "high"),
        "sonnet": ("claude-sonnet-5-5-medium", "medium"),
        "sonnet-high": ("claude-sonnet-5-5-high", "high"),
        "gpt-oss": ("gpt-oss-120b-medium", "medium"),
    }
    if req in shorthand_map:
        return shorthand_map[req]

    if req and req != "auto":
        return requested_model.strip(), resolve_compatible_effort(requested_model.strip())

    # Dynamic Smart Model Router (`route_model.py`)
    router_candidates = (
        Path("~/.agents/skills/smart-model-router/scripts/route_model.py"),
        Path("~/.agents/skills/smart-model-router/scripts/route_model.py"),
    )
    for router_path in router_candidates:
        if router_path.exists():
            try:
                spec = importlib.util.spec_from_file_location("pocket_route_model", str(router_path))
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules["pocket_route_model"] = mod
                    spec.loader.exec_module(mod)
                    if hasattr(mod, "classify_prompt"):
                        dec = mod.classify_prompt(prompt_text, channel="iphone-cli")
                        chosen_model = str(dec.cli_model or dec.model)
                        return chosen_model, resolve_compatible_effort(chosen_model, str(dec.effort))
            except Exception as exc:
                logger.debug("Smart model router fallback: %s", exc)
            break

    # Built-in deterministic fallback (no router installed, e.g. on a fresh fork).
    # `agy` rejects the literal model name "auto", so never pass it through: pick a real model.
    words = prompt_text.strip().split()
    if len(words) <= 8 and prompt_text.strip().endswith("?"):
        return "gemini-3.8-flash-high", "high"
    fallback_model = DEFAULT_MODEL if DEFAULT_MODEL.strip().lower() not in ("", "auto") else "gemini-4-argon-high"
    return fallback_model, resolve_compatible_effort(fallback_model, DEFAULT_EFFORT)


def discover_or_create_iphone_cli_channel() -> str:
    """
    Find `#⌨️・cli` (or `#⌨️・iphone-cli`) in Miths DOOOD,
    creating it under category `` if missing.
    """
    channels = discord_ctl.api_request("GET", f"/guilds/{DISCORD_GUILD_ID}/channels")
    if isinstance(channels, list):
        for ch in channels:
            if not isinstance(ch, dict) or ch.get("type") != 0:
                continue
            ch_name = str(ch.get("name") or "").lower()
            if ch_name in ("cli", "⌨️・cli", "iphone-cli", "⌨️・iphone-cli") or "iphone-cli" in ch_name or ch_name.endswith("・cli"):
                if ch.get("id"):
                    return str(ch["id"])

    create_payload: dict[str, Any] = {
        "name": IPHONE_CLI_CHANNEL_NAME,
        "type": 0,
        "parent_id": IPHONE_CLI_CATEGORY_ID,
        "topic": "📱 Antigravity Pocket CLI — iPhone 1-Tap Pairing & Live Command Sync",
    }
    try:
        created = discord_ctl.api_request(
            "POST", f"/guilds/{DISCORD_GUILD_ID}/channels", create_payload
        )
    except RuntimeError:
        create_payload.pop("parent_id", None)
        created = discord_ctl.api_request(
            "POST", f"/guilds/{DISCORD_GUILD_ID}/channels", create_payload
        )

    if isinstance(created, dict) and created.get("id"):
        return str(created["id"])
    raise RuntimeError("Unable to discover or provision #⌨️・iphone-cli channel")


_CONV_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,80}$")
_VERBATIM_RE = re.compile(r"<user_verbatim>(.*?)</user_verbatim>", re.DOTALL)
_USER_REQ_RE = re.compile(r"<USER_REQUEST>(.*?)</USER_REQUEST>", re.DOTALL)


def _clean_transcript_user_input(raw_text: str) -> str:
    m_verb = _VERBATIM_RE.search(raw_text)
    if m_verb:
        return scrub_secrets(m_verb.group(1).strip())
    m_req = _USER_REQ_RE.search(raw_text)
    if m_req:
        inner = m_req.group(1).strip()
        # Strip nested flash_mastered_prompt XML if present without user_verbatim
        inner = re.sub(r"<flash_mastered_prompt>.*?</flash_mastered_prompt>", "", inner, flags=re.DOTALL).strip()
        return scrub_secrets(inner)
    cleaned = re.sub(r"<ADDITIONAL_METADATA>.*?</ADDITIONAL_METADATA>", "", raw_text, flags=re.DOTALL)
    cleaned = re.sub(r"<USER_SETTINGS_CHANGE>.*?</USER_SETTINGS_CHANGE>", "", cleaned, flags=re.DOTALL)
    return scrub_secrets(cleaned.strip())


def list_antigravity_conversations(limit_per_source: int = 18) -> list[dict[str, Any]]:
    """Query recent top-level conversations from both WSL CLI and Windows Desktop Antigravity App."""
    items: list[dict[str, Any]] = []
    sources: tuple[tuple[str, str, Path], ...] = (
        ("cli", "WSL CLI", CLI_APP_DATA_DIR / "conversation_summaries.db"),
        ("app", "Desktop App", WIN_APP_DATA_DIR / "conversation_summaries.db"),
    )
    for src_key, src_label, db_file in sources:
        try:
            if not db_file.is_file():
                continue
            conn = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True, timeout=2.0)
            try:
                rows = conn.execute(
                    "SELECT conversation_id, title, substr(preview, 1, 140), step_count, "
                    "last_modified_time, status FROM conversation_summaries "
                    "WHERE nesting_depth = 0 AND step_count > 0 "
                    "ORDER BY last_modified_time DESC LIMIT ?",
                    (int(limit_per_source),),
                ).fetchall()
            finally:
                conn.close()
            for conv_id, title, preview, steps, mod_time, status in rows:
                cid = str(conv_id or "").strip()
                if not cid:
                    continue
                items.append(
                    {
                        "conversation_id": cid,
                        "title": scrub_secrets(str(title or preview or cid[:8]).strip())[:90],
                        "preview": scrub_secrets(str(preview or "").strip())[:140],
                        "step_count": int(steps or 0),
                        "last_modified": str(mod_time or ""),
                        "running": "RUNNING" in str(status or "").upper(),
                        "source": src_key,
                        "source_label": src_label,
                    }
                )
        except Exception as exc:
            logger.debug("Conversation DB read skipped (%s): %s", src_key, exc)
    items.sort(key=lambda x: x.get("last_modified") or "", reverse=True)
    return items[:32]


def load_conversation_transcript(
    conv_id: str, source: str = "cli", max_turns: int = 18
) -> list[dict[str, str]]:
    """Extract clean user/assistant turns from Antigravity `transcript.jsonl` (CLI or Desktop App)."""
    cid = str(conv_id or "").strip()
    if not _CONV_ID_RE.match(cid):
        return []
    roots = (
        [WIN_APP_DATA_DIR / "brain", CLI_APP_DATA_DIR / "brain"]
        if source == "app"
        else [CLI_APP_DATA_DIR / "brain", WIN_APP_DATA_DIR / "brain"]
    )
    tx_file: Path | None = None
    for b_root in roots:
        cand_full = b_root / cid / ".system_generated" / "logs" / "transcript_full.jsonl"
        cand_comp = b_root / cid / ".system_generated" / "logs" / "transcript.jsonl"
        if cand_full.is_file():
            tx_file = cand_full
            break
        if cand_comp.is_file():
            tx_file = cand_comp
            break
    if tx_file is None:
        return []

    turns: list[dict[str, Any]] = []
    pending_user: str = ""
    pending_reply: list[str] = []
    pending_tools: list[str] = []
    last_step_had_tool_calls: bool = False
    try:
        tx_mtime = tx_file.stat().st_mtime
        with tx_file.open("r", encoding="utf-8", errors="replace") as fh:
            for raw_ln in fh:
                ln = raw_ln.strip()
                if not ln.startswith("{"):
                    continue
                try:
                    step = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                st_type = step.get("type")
                content = str(step.get("content") or "").strip()
                if st_type == "USER_INPUT" and content:
                    cleaned_new = _clean_transcript_user_input(content)
                    if pending_user:
                        if pending_reply:
                            turns.append(
                                {
                                    "prompt": pending_user,
                                    "response": "\n\n".join(pending_reply).strip(),
                                    "tools": list(pending_tools),
                                    "in_progress": False,
                                }
                            )
                        elif not cleaned_new.startswith(pending_user[:35]):
                            turns.append(
                                {
                                    "prompt": pending_user,
                                    "response": "(Tool-only or interrupted turn)",
                                    "tools": list(pending_tools),
                                    "in_progress": False,
                                }
                            )
                    pending_user = cleaned_new
                    pending_reply = []
                    pending_tools = []
                    last_step_had_tool_calls = True
                elif st_type == "PLANNER_RESPONSE" and pending_user:
                    tcalls = step.get("tool_calls")
                    if isinstance(tcalls, list) and tcalls:
                        last_step_had_tool_calls = True
                        for tc in tcalls:
                            if isinstance(tc, dict):
                                tname = str(tc.get("name") or tc.get("tool_name") or "tool")
                                args = tc.get("arguments") or tc.get("args") or {}
                                summary_lbl = (
                                    str(args.get("toolSummary") or "")
                                    if isinstance(args, dict)
                                    else ""
                                )
                                pending_tools.append(summary_lbl or tname)
                    else:
                        last_step_had_tool_calls = False
                    if content:
                        pending_reply.append(scrub_secrets(content))
        if pending_user:
            is_live = (not pending_reply or last_step_had_tool_calls) and (
                (time.time() - tx_mtime) < 90.0
            )
            turns.append(
                {
                    "prompt": pending_user,
                    "response": "\n\n".join(pending_reply).strip() or ("Working..." if is_live else "(In progress...)"),
                    "tools": list(pending_tools),
                    "in_progress": bool(is_live),
                }
            )
    except OSError:
        return []
    return turns[-max_turns:]


class PocketCLIState:
    """Thread-safe session, PIN pairing, CWD, conversation, and active subprocess state."""

    def __init__(
        self,
        sessions_file: Path = SESSIONS_FILE,
        tunnel_url_file: Path = TUNNEL_URL_FILE,
        initial_cwd: Path | str | None = None,
        agy_bin_path: str = AGY_BIN_PATH,
        owner_pin: str = OWNER_PIN,
    ) -> None:
        self.sessions_file = sessions_file
        self.tunnel_url_file = tunnel_url_file
        self.agy_bin_path = agy_bin_path
        self.owner_pin: str = str(owner_pin or OWNER_PIN).strip()

        default_dir = Path(initial_cwd) if initial_cwd else BRIDGE_DIR
        if not default_dir.exists():
            default_dir = Path.cwd()
        self.current_cwd: str = str(default_dir.resolve())
        self.previous_cwd: str = self.current_cwd
        self.current_conv_id: str = ""
        self._cached_channel_id: str | None = None

        self._state_lock = threading.Lock()
        self._proc_lock = threading.Lock()
        self._active_proc: subprocess.Popen[str] | None = None
        self._cancel_requested: bool = False
        self._fold_in_requested: bool = False
        self.active_turn_mutated: bool = False
        self.turn_id: int = 0
        self.turn_in_progress: bool = False
        self.live_prompt: str = ""
        self.live_mode: str = "agy"
        self.live_started_at: float = 0.0
        self.live_enhanced: dict[str, Any] | None = None
        self.live_tools: list[str] = []
        self.live_text: str = ""
        self.last_turn_result: dict[str, Any] | None = None
        self.ephemeral_files: set[str] = set()
        self.btw_notes: list[str] = []
        self.app_conv_bridges: dict[str, str] = {}

        self.sessions_file.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_sessions_file()
        self._restore_runtime_context(initial_cwd=initial_cwd)

    def queue_btw_note(self, note: str) -> int:
        cleaned = scrub_secrets(note.strip())
        if not cleaned:
            return len(self.btw_notes)
        with self._state_lock:
            self.btw_notes.append(cleaned)
            count = len(self.btw_notes)
            try:
                btw_file = WORKSPACE_DIR / ".live_btw_notes.md"
                btw_file.parent.mkdir(parents=True, exist_ok=True)
                btw_file.write_text(
                    "# Live /btw Context Notes from iPhone\n"
                    + "\n".join(f"- {n}" for n in self.btw_notes)
                    + "\n",
                    encoding="utf-8",
                )
            except OSError:
                pass
        return count

    def pop_btw_notes(self) -> list[str]:
        with self._state_lock:
            notes = list(self.btw_notes)
            self.btw_notes.clear()
            try:
                (WORKSPACE_DIR / ".live_btw_notes.md").unlink(missing_ok=True)
            except OSError:
                pass
        return notes

    def register_ephemeral_upload(self, file_path: Path | str) -> None:
        with self._state_lock:
            self.ephemeral_files.add(str(file_path))

    def cleanup_ephemeral_uploads(self) -> int:
        """Delete temporary uploaded photos/files right after AGY finishes reading them."""
        removed = 0
        with self._state_lock:
            targets = list(self.ephemeral_files)
            self.ephemeral_files.clear()
        for p_str in targets:
            try:
                p = Path(p_str)
                if p.is_file():
                    p.unlink(missing_ok=True)
                    removed += 1
            except OSError:
                pass
        try:
            if EPHEMERAL_UPLOADS_DIR.is_dir():
                cutoff = time.time() - 600.0
                for child in EPHEMERAL_UPLOADS_DIR.iterdir():
                    try:
                        if child.is_file() and child.stat().st_mtime < cutoff:
                            child.unlink(missing_ok=True)
                            removed += 1
                    except OSError:
                        pass
        except OSError:
            pass
        return removed

    def _default_store(self) -> dict[str, Any]:
        return {
            "sessions": [],
            "active_pin": None,
            "request_timestamps": [],
            "conversation_id": "",
            "cwd": "",
            "app_conv_bridges": {},
            "vapid": {},
            "push_subscriptions": [],
        }

    def _restore_runtime_context(self, *, initial_cwd: Path | str | None = None) -> None:
        with self._state_lock:
            store = self._load_store_unlocked()
            saved_conv = str(store.get("conversation_id") or "").strip()
            if saved_conv:
                self.current_conv_id = saved_conv
            bridges = store.get("app_conv_bridges")
            if isinstance(bridges, dict):
                self.app_conv_bridges = {str(k): str(v) for k, v in bridges.items() if k and v}
            if initial_cwd is None:
                saved_cwd = str(store.get("cwd") or "").strip()
                if saved_cwd and Path(saved_cwd).is_dir():
                    self.current_cwd = str(Path(saved_cwd).resolve())
                    self.previous_cwd = self.current_cwd

    def _persist_runtime_context(self) -> None:
        with self._state_lock:
            store = self._load_store_unlocked()
            store["conversation_id"] = self.current_conv_id
            store["cwd"] = self.current_cwd
            store["app_conv_bridges"] = dict(self.app_conv_bridges)
            self._write_store_unlocked(store)

    def _ensure_sessions_file(self) -> None:
        with self._state_lock:
            if not self.sessions_file.exists():
                self._write_store_unlocked(self._default_store())
            else:
                try:
                    os.chmod(self.sessions_file, 0o600)
                except OSError:
                    pass

    def _load_store_unlocked(self) -> dict[str, Any]:
        if not self.sessions_file.exists():
            return self._default_store()
        try:
            raw = json.loads(self.sessions_file.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                raw.setdefault("sessions", [])
                raw.setdefault("active_pin", None)
                raw.setdefault("request_timestamps", [])
                raw.setdefault("vapid", {})
                raw.setdefault("push_subscriptions", [])
                return raw
        except (OSError, json.JSONDecodeError):
            pass
        return self._default_store()

    def _write_store_unlocked(self, data: dict[str, Any]) -> None:
        self.sessions_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=".pocket_sessions_", dir=str(self.sessions_file.parent)
        )
        tmp_path = Path(tmp_name)
        try:
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
            os.replace(tmp_path, self.sessions_file)
            try:
                os.chmod(self.sessions_file, 0o600)
            except OSError:
                pass
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    def read_tunnel_url(self) -> str:
        return read_tunnel_url(self.tunnel_url_file)

    def verify_session_token(self, token: str | None, now: float | None = None) -> bool:
        """Constant-time validation of `<tok>` SHA-256 hash against non-expired stored sessions."""
        if not token or not isinstance(token, str):
            return False
        ts_now = time.time() if now is None else now
        cand_hash = _sha256_hex(token)

        with self._state_lock:
            store = self._load_store_unlocked()
            valid_sessions: list[dict[str, Any]] = []
            matched = False
            dirty = False

            for entry in store.get("sessions", []):
                if not isinstance(entry, dict):
                    dirty = True
                    continue
                exp = float(entry.get("expires_at") or 0.0)
                stored_hash = str(entry.get("token_sha256") or "")
                if exp <= ts_now or not stored_hash:
                    dirty = True
                    continue
                valid_sessions.append(entry)
                if hmac.compare_digest(cand_hash, stored_hash):
                    matched = True

            if dirty:
                store["sessions"] = valid_sessions
                self._write_store_unlocked(store)
            return matched

    def create_pairing_code(self, now: float | None = None) -> tuple[bool, str, int]:
        """
        Rate-limited (max 3 per 300s) 6-digit PIN generator.
        Returns `(allowed, pin_or_error, expires_or_retry_seconds)`.
        """
        ts_now = time.time() if now is None else now
        with self._state_lock:
            store = self._load_store_unlocked()
            recent = [
                float(t)
                for t in store.get("request_timestamps", [])
                if isinstance(t, (int, float)) and (ts_now - float(t)) < PIN_RATE_WINDOW_SECONDS
            ]
            if len(recent) >= PIN_MAX_REQUESTS_PER_WINDOW:
                oldest = min(recent)
                retry_after = max(1, int(PIN_RATE_WINDOW_SECONDS - (ts_now - oldest)))
                store["request_timestamps"] = recent
                self._write_store_unlocked(store)
                return False, "Rate limit exceeded (max 3 pairing codes per 5 minutes).", retry_after

            code = f"{secrets.randbelow(900000) + 100000}"
            recent.append(ts_now)
            store["request_timestamps"] = recent
            store["active_pin"] = {
                "pin_sha256": _sha256_hex(code),
                "expires_at": ts_now + PIN_TTL_SECONDS,
                "attempts": 0,
            }
            self._write_store_unlocked(store)
            return True, code, PIN_TTL_SECONDS

    def invalidate_active_pin(self) -> None:
        with self._state_lock:
            store = self._load_store_unlocked()
            store["active_pin"] = None
            self._write_store_unlocked(store)

    def mint_direct_session_token(self, now: float | None = None) -> str:
        """Mint a valid 90-day session token for trusted local / Tailscale connections."""
        ts_now = time.time() if now is None else now
        tok = secrets.token_urlsafe(32)
        with self._state_lock:
            store = self._load_store_unlocked()
            sessions = [
                s
                for s in store.get("sessions", [])
                if isinstance(s, dict) and float(s.get("expires_at") or 0.0) > ts_now
            ]
            sessions.append(
                {
                    "token_sha256": _sha256_hex(tok),
                    "created_at": ts_now,
                    "expires_at": ts_now + SESSION_TTL_SECONDS,
                }
            )
            store["sessions"] = sessions[-20:]
            self._write_store_unlocked(store)
        return tok

    def verify_pairing_code(
        self, submitted_code: str, now: float | None = None
    ) -> tuple[bool, str, int]:
        """
        Verify PIN via `hmac.compare_digest`. Matches either the active 1-time PIN
        or the direct local owner PIN / passphrase without requiring Discord.
        Returns `(ok, session_token_or_error, attempts_remaining)`.
        """
        ts_now = time.time() if now is None else now
        clean_code = (submitted_code or "").strip()
        cand_hash = _sha256_hex(clean_code)

        # 1. Direct Owner PIN check (allows instant zero-Discord login)
        resolved_pin = self.owner_pin or os.getenv("POCKET_CLI_PIN", "").strip()
        if not resolved_pin:
            try:
                for env_line in (BRIDGE_DIR / ".env").read_text(encoding="utf-8").splitlines():
                    if env_line.strip().startswith("POCKET_CLI_PIN="):
                        resolved_pin = env_line.split("=", 1)[1].strip().strip('"').strip("'")
                        self.owner_pin = resolved_pin
                        break
            except Exception:
                pass

        if resolved_pin and clean_code and (
            clean_code == resolved_pin
            or hmac.compare_digest(cand_hash, _sha256_hex(resolved_pin))
        ):
            tok = self.mint_direct_session_token(now=ts_now)
            return True, tok, PIN_MAX_VERIFY_ATTEMPTS

        with self._state_lock:
            store = self._load_store_unlocked()
            pin_info = store.get("active_pin")
            if not isinstance(pin_info, dict):
                return False, "No active pairing code. Request a new code first.", 0

            expires_at = float(pin_info.get("expires_at") or 0.0)
            attempts = int(pin_info.get("attempts") or 0)
            stored_hash = str(pin_info.get("pin_sha256") or "")

            if ts_now > expires_at or attempts >= PIN_MAX_VERIFY_ATTEMPTS or not stored_hash:
                store["active_pin"] = None
                self._write_store_unlocked(store)
                return False, "Pairing code expired or invalidated. Request a new code.", 0

            is_valid = bool(clean_code) and hmac.compare_digest(cand_hash, stored_hash)
            if not is_valid:
                attempts += 1
                remaining = max(0, PIN_MAX_VERIFY_ATTEMPTS - attempts)
                if attempts >= PIN_MAX_VERIFY_ATTEMPTS:
                    store["active_pin"] = None
                else:
                    pin_info["attempts"] = attempts
                    store["active_pin"] = pin_info
                self._write_store_unlocked(store)
                return False, "Invalid pairing code.", remaining

            # Valid match -> consume PIN and mint 90-day session token
            store["active_pin"] = None
            tok = secrets.token_urlsafe(32)
            sessions = [
                s
                for s in store.get("sessions", [])
                if isinstance(s, dict) and float(s.get("expires_at") or 0.0) > ts_now
            ]
            sessions.append(
                {
                    "token_sha256": _sha256_hex(tok),
                    "created_at": ts_now,
                    "expires_at": ts_now + SESSION_TTL_SECONDS,
                }
            )
            store["sessions"] = sessions[-20:]
            self._write_store_unlocked(store)
            return True, tok, PIN_MAX_VERIFY_ATTEMPTS

    def get_discord_channel_id(self) -> str:
        if self._cached_channel_id:
            return self._cached_channel_id
        ch_id = discover_or_create_iphone_cli_channel()
        self._cached_channel_id = ch_id
        return ch_id

    def send_pairing_code_to_discord(self, code: str) -> None:
        ch_id = self.get_discord_channel_id()
        msg_content = (
            "Your 6-digit Antigravity Pocket CLI pairing code is ready.\n\n"
            f"<@{OWNER_USER_ID}> Enter **`{code}`** in Pocket CLI on your iPhone "
            "(expires in 5 minutes)."
        )
        discord_ctl.api_request(
            "POST",
            f"/channels/{ch_id}/messages",
            {"content": msg_content},
        )

    def sync_turn_to_discord_async(
        self,
        *,
        mode: str,
        raw_input: str,
        output_text: str,
        duration_ms: int,
        receipt: dict[str, Any] | None = None,
        exit_code: int | None = None,
        cwd: str | None = None,
        model: str | None = None,
    ) -> None:
        """Spawn a daemon thread to post a compact, secret-scrubbed embed into `#⌨️・iphone-cli`."""

        def _worker() -> None:
            try:
                ch_id = self.get_discord_channel_id()
                safe_in = scrub_secrets(raw_input).strip()
                if len(safe_in) > 350:
                    safe_in = safe_in[:347] + "..."

                safe_out = scrub_secrets(output_text).strip() or "(no output)"
                if len(safe_out) > DISCORD_OUTPUT_MAX_CHARS:
                    safe_out = safe_out[: DISCORD_OUTPUT_MAX_CHARS - 16] + "\n... [truncated]"

                if mode == "agy":
                    stamp = (
                        str(receipt.get("footer_stamp"))
                        if isinstance(receipt, dict) and receipt.get("footer_stamp")
                        else "⚡ Pocket CLI AGY"
                    )
                    all_ok = bool(receipt.get("all_passed", True)) if isinstance(receipt, dict) else True
                    embed: dict[str, Any] = {
                        "title": "Pocket CLI • Antigravity Turn",
                        "color": 0x10B981 if all_ok else 0xF59E0B,
                        "description": safe_out,
                        "fields": [
                            {"name": "Prompt", "value": f"`{safe_in}`", "inline": False},
                            {
                                "name": "Stage-0 Pipeline",
                                "value": f"{stamp} • `{model or 'auto'}` • `{duration_ms} ms`",
                                "inline": False,
                            },
                        ],
                    }
                else:
                    rc = 0 if exit_code is None else int(exit_code)
                    safe_cwd = scrub_secrets(cwd or self.current_cwd)
                    embed = {
                        "title": "Pocket CLI • WSL Shell Command",
                        "color": 0x10B981 if rc == 0 else 0xEF4444,
                        "description": f"```text\n{safe_out[:1450]}\n```",
                        "fields": [
                            {"name": "Command", "value": f"`$ {safe_in}`", "inline": False},
                            {
                                "name": "Exit & CWD",
                                "value": f"Exit `{rc}` • `{safe_cwd}` • `{duration_ms} ms`",
                                "inline": False,
                            },
                        ],
                    }

                discord_ctl.api_request(
                    "POST",
                    f"/channels/{ch_id}/messages",
                    {
                        "content": f"<@{OWNER_USER_ID}> Pocket CLI synced a {mode.upper()} turn from your iPhone.",
                        "embeds": [embed],
                    },
                )
            except Exception as exc:
                logger.warning("Discord #iphone-cli sync skipped: %s", scrub_secrets(str(exc)))

        threading.Thread(target=_worker, name="pocket-discord-sync", daemon=True).start()

    def get_or_create_vapid(self) -> tuple[str, str]:
        """
        Return (public_key_b64, private_pem_str).
        Generates and persists an elliptic-curve (P-256) VAPID keypair in .pocket_cli_sessions.json.
        """
        with self._state_lock:
            store = self._load_store_unlocked()
            vapid_info = store.get("vapid") or {}
            priv_pem = str(vapid_info.get("private_pem") or "").strip()
            pub_b64 = str(vapid_info.get("public_key") or "").strip()

            if priv_pem and pub_b64:
                return pub_b64, priv_pem

            from py_vapid import Vapid  # type: ignore[import-untyped]
            from cryptography.hazmat.primitives import serialization  # type: ignore[import-untyped]

            v = Vapid()
            v.generate_keys()
            priv_pem = v.private_pem().decode("utf-8")
            raw_pub = v.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
            pub_b64 = base64.urlsafe_b64encode(raw_pub).rstrip(b"=").decode("ascii")

            store["vapid"] = {"private_pem": priv_pem, "public_key": pub_b64}
            self._write_store_unlocked(store)
            return pub_b64, priv_pem

    def save_push_subscription(self, sub: dict[str, Any]) -> None:
        endpoint = str(sub.get("endpoint") or "").strip()
        if not endpoint:
            return
        with self._state_lock:
            store = self._load_store_unlocked()
            subs: list[dict[str, Any]] = list(store.get("push_subscriptions", []))
            subs = [s for s in subs if isinstance(s, dict) and s.get("endpoint") != endpoint]
            subs.append(sub)
            store["push_subscriptions"] = subs
            self._write_store_unlocked(store)

    def remove_push_subscription(self, endpoint: str) -> None:
        if not endpoint:
            return
        with self._state_lock:
            store = self._load_store_unlocked()
            subs: list[dict[str, Any]] = list(store.get("push_subscriptions", []))
            subs = [s for s in subs if isinstance(s, dict) and s.get("endpoint") != endpoint]
            store["push_subscriptions"] = subs
            self._write_store_unlocked(store)

    def send_push_notification_async(
        self,
        title: str,
        body: str,
        *,
        tag: str = "turn",
        url: str = "/cli",
    ) -> None:
        """Asynchronously dispatch encrypted VAPID Web Push notification to all subscribed iOS/desktop devices."""
        def _worker() -> None:
            try:
                with self._state_lock:
                    store = self._load_store_unlocked()
                    subs = list(store.get("push_subscriptions", []))

                # Nothing subscribed (push never enabled) -> do no work and never require pywebpush.
                if not subs:
                    return

                pub_b64, priv_pem = self.get_or_create_vapid()

                from py_vapid import Vapid  # type: ignore[import-untyped]
                from pywebpush import webpush, WebPushException  # type: ignore[import-untyped]

                v_inst = Vapid.from_pem(priv_pem.encode("utf-8"))
                claims = {"sub": "mailto:devon@mith-studio.local"}
                payload_str = json.dumps({
                    "title": title,
                    "body": body,
                    "tag": tag,
                    "url": url,
                    "timestamp": int(time.time() * 1000),
                })

                dead_endpoints: list[str] = []

                for sub in subs:
                    if not isinstance(sub, dict) or not sub.get("endpoint"):
                        continue
                    try:
                        webpush(
                            subscription_info=sub,
                            data=payload_str,
                            vapid_private_key=v_inst,
                            vapid_claims=claims,
                            ttl=3600,
                            timeout=8,
                        )
                        logger.info("WebPush dispatched successfully to %s", str(sub.get("endpoint"))[:45])
                    except WebPushException as w_exc:
                        code = getattr(getattr(w_exc, "response", None), "status_code", None)
                        logger.warning("WebPush failed (status=%s): %s", code, w_exc)
                        if code in (404, 410):
                            dead_endpoints.append(str(sub.get("endpoint")))
                    except Exception as p_exc:
                        logger.warning("WebPush transport exception: %s", p_exc)

                if dead_endpoints:
                    with self._state_lock:
                        store = self._load_store_unlocked()
                        current_subs = store.get("push_subscriptions", [])
                        store["push_subscriptions"] = [
                            s for s in current_subs
                            if isinstance(s, dict) and s.get("endpoint") not in dead_endpoints
                        ]
                        self._write_store_unlocked(store)
            except Exception as exc:
                logger.warning("WebPush dispatcher error: %s", exc)

        threading.Thread(target=_worker, name="pocket-webpush-worker", daemon=True).start()

    def _register_proc(self, proc: subprocess.Popen[str]) -> None:
        with self._proc_lock:
            self._active_proc = proc
            self._cancel_requested = False
            self._fold_in_requested = False

    def _unregister_proc(self, proc: subprocess.Popen[str]) -> None:
        with self._proc_lock:
            if self._active_proc is proc:
                self._active_proc = None

    def request_fold_in(self) -> bool:
        """Signal the active `agy` subprocess to stop so `run_agy_turn` immediately merges newly sent messages."""
        with self._proc_lock:
            self._fold_in_requested = True
            proc = self._active_proc
            if proc is None or proc.poll() is not None:
                return False
            try:
                proc.terminate()
                return True
            except OSError:
                return False

    def cancel_active_process(self) -> bool:
        """Terminate active `agy` or `bash` subprocess cleanly (`SIGINT` -> `SIGTERM` -> `SIGKILL`)."""
        with self._proc_lock:
            proc = self._active_proc
            if proc is None or proc.poll() is not None:
                self._active_proc = None
                return False
            self._cancel_requested = True

        try:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=1.5)
                return True
            except subprocess.TimeoutExpired:
                pass
            proc.terminate()
            try:
                proc.wait(timeout=1.5)
                return True
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1.0)
                return True
        except OSError:
            return False
        finally:
            self._unregister_proc(proc)

    def clear_conversation(self) -> None:
        self.current_conv_id = ""
        self._persist_runtime_context()

    def run_agy_turn(
        self,
        raw_in: str,
        *,
        enhance: bool = DEFAULT_ENHANCE,
        sync_discord: bool = False,
        requested_model: str = "auto",
        target_conv_id: str | None = None,
        conv_source: str = "cli",
        emit: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Execute Stage-0 `prompt_master` enhancement + `agy --output-format stream-json` turn."""
        t0 = time.monotonic()
        send = emit or (lambda _evt: None)

        # Drain any queued `/btw` live notes into this turn's prompt
        queued_btw = self.pop_btw_notes()
        effective_raw_in = raw_in
        if queued_btw:
            btw_block = "\n".join(f"- {n}" for n in queued_btw)
            effective_raw_in = f"{raw_in}\n\n[Additional Live /btw Context from User:\n{btw_block}]"

        # Resolve per-tab conversation ID (and bridge Windows Desktop App conversations seamlessly)
        active_conv_id = self.current_conv_id if target_conv_id is None else str(target_conv_id).strip()
        bridging_from_app_id = ""
        if active_conv_id and conv_source == "app":
            mapped_cli = self.app_conv_bridges.get(active_conv_id, "")
            if mapped_cli:
                active_conv_id = mapped_cli
            else:
                bridging_from_app_id = active_conv_id
                recent_app_turns = load_conversation_transcript(active_conv_id, source="app", max_turns=4)
                if recent_app_turns:
                    ctx_snippets = []
                    for t_obj in recent_app_turns:
                        u_s = str(t_obj.get("prompt") or "")[:350]
                        a_s = str(t_obj.get("response") or "")[:550]
                        ctx_snippets.append(f"User: {u_s}\nAssistant: {a_s}")
                    effective_raw_in = (
                        "[Continuing Desktop Antigravity App Conversation — Recent Context:\n"
                        + "\n---\n".join(ctx_snippets)
                        + "]\n\n"
                        + effective_raw_in
                    )
                active_conv_id = ""

        resolved_model, resolved_effort = resolve_model_and_effort(effective_raw_in, requested_model)
        norm_in = prompt_master.normalize_mobile_text(raw_in)
        chosen_id, _profile = prompt_master.select_specialized_agent(norm_in, "iphone-cli")
        hier = prompt_master.get_agent_hierarchy_info(chosen_id)

        current_prompt = effective_raw_in
        combined_responses: list[str] = []
        resolved_conv_id = active_conv_id
        mastered = current_prompt
        pass_index = 0
        # Quota-aware failover state (shared with Discord bot via model_failover state file)
        failover_override: tuple[str, str] | None = None
        tried_models: list[str] = []
        first_requested_model = ""

        while True:
            pass_index += 1
            self.active_turn_mutated = False
            self._fold_in_requested = False

            resolved_model, resolved_effort = resolve_model_and_effort(current_prompt, requested_model)
            if not first_requested_model:
                first_requested_model = resolved_model
            if failover_override:
                resolved_model, resolved_effort = failover_override
            else:
                wanted_model = resolved_model
                resolved_model, resolved_effort = model_failover.pick_available(resolved_model, resolved_effort)
                if resolved_model != wanted_model:
                    send(
                        {
                            "type": "tool",
                            "name": f"{model_failover.friendly_name(wanted_model)} quota maxed → using {model_failover.friendly_name(resolved_model)}",
                        }
                    )
            if enhance:
                mastered = prompt_master.master_user_prompt(
                    raw_prompt=current_prompt,
                    channel_name="iphone-cli",
                    target_model=resolved_model,
                )
            else:
                mastered = current_prompt

            if pass_index == 1:
                send(
                    {
                        "type": "enhanced",
                        "enhanced_active": bool(enhance),
                        "raw": scrub_secrets(raw_in),
                        "clarified_intent": scrub_secrets(norm_in),
                        "agent_id": chosen_id,
                        "tier": hier.get("tier", "primary"),
                        "pod": hier.get("pod", "default"),
                        "model": resolved_model,
                        "effort": resolved_effort,
                    }
                )

            # Auto-rotate bloated agy sessions (>1.2 MB transcript) so turns stay fast
            if active_conv_id:
                brain_tx = (
                    CLI_APP_DATA_DIR
                    / "brain"
                    / active_conv_id
                    / ".system_generated"
                    / "logs"
                    / "transcript_full.jsonl"
                )
                try:
                    if brain_tx.is_file() and brain_tx.stat().st_size > AGY_MAX_TRANSCRIPT_BYTES:
                        logger.info(
                            "Auto-rotating bloated Pocket CLI agy session %s (%d bytes)",
                            active_conv_id,
                            brain_tx.stat().st_size,
                        )
                        if self.last_turn_result and self.last_turn_result.get("response"):
                            prev_snip = str(self.last_turn_result["response"])[:600]
                            mastered = f"[Previous Turn Context: {prev_snip}]\n\n{mastered}"
                        active_conv_id = ""
                except OSError:
                    pass

            argv: list[str] = [
                self.agy_bin_path,
                "--print",
                mastered,
                "--model",
                resolved_model,
                "--effort",
                resolved_effort,
                "--output-format",
                "stream-json",
                "--disable-slash-commands",
                "--dangerously-skip-permissions",
            ]
            for extra_dir in AGY_EXTRA_DIRS:
                # Only grant directories that actually exist on this machine (forks get none by default).
                if Path(extra_dir).is_dir():
                    argv.extend(["--add-dir", extra_dir])
            if active_conv_id:
                argv.extend(["--conversation", active_conv_id])

            env = os.environ.copy()
            env["NO_COLOR"] = "1"

            accumulated = ""
            final_response = ""
            stderr_lines: list[str] = []
            timed_out = False
            last_activity_ts = time.monotonic()
            stop_watchdog = threading.Event()

            proc = subprocess.Popen(
                argv,
                cwd=self.current_cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                shell=False,
                env=env,
            )
            self._register_proc(proc)

            def _idle_watchdog_loop() -> None:
                nonlocal timed_out
                check_step = min(1.0, max(0.05, AGY_TIMEOUT_SECONDS / 4.0))
                while not stop_watchdog.wait(check_step):
                    if proc.poll() is not None:
                        break
                    if (time.monotonic() - last_activity_ts) >= AGY_TIMEOUT_SECONDS:
                        timed_out = True
                        try:
                            proc.terminate()
                            proc.wait(timeout=2.0)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                        except OSError:
                            pass
                        break

            watchdog = threading.Thread(target=_idle_watchdog_loop, name="agy-idle-watchdog", daemon=True)
            watchdog.start()

            def _drain_stderr() -> None:
                assert proc.stderr is not None
                try:
                    for err_ln in proc.stderr:
                        if len(stderr_lines) < 50:
                            stderr_lines.append(err_ln.rstrip("\r\n"))
                except ValueError:
                    pass

            stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
            stderr_thread.start()

            try:
                assert proc.stdout is not None
                for raw_line in proc.stdout:
                    last_activity_ts = time.monotonic()
                    line = raw_line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if evt.get("conversation_id") and not resolved_conv_id:
                        resolved_conv_id = str(evt["conversation_id"])

                    event_type = evt.get("event")
                    if event_type == "step_update":
                        su = evt.get("step_update") or {}
                        if su.get("conversation_id") and not resolved_conv_id:
                            resolved_conv_id = str(su["conversation_id"])

                        step_type = su.get("step_type")
                        if step_type == "agent_response" and su.get("text_delta"):
                            self.active_turn_mutated = True
                            delta_text = scrub_secrets(str(su["text_delta"]))
                            accumulated += delta_text
                            send({"type": "chunk", "text": delta_text})
                        elif step_type == "tool":
                            raw_tool = (
                                su.get("tool_name")
                                or (su.get("tool_info") or {}).get("name")
                                or "tool"
                            )
                            if str(raw_tool) not in ("read_file", "search_web", "grep_search", "find_by_name", "list_dir"):
                                self.active_turn_mutated = True
                            params = (su.get("tool_info") or {}).get("parameters") or {}
                            tool_summary = params.get("toolSummary") or params.get("Description")
                            fpath = (
                                params.get("Path")
                                or params.get("TargetFile")
                                or params.get("AbsolutePath")
                            )
                            q_str = params.get("query")
                            if isinstance(tool_summary, str) and tool_summary.strip():
                                tool_label = tool_summary.strip()
                            elif isinstance(fpath, str) and fpath:
                                tool_label = f"{raw_tool} ({Path(fpath).name})"
                            elif isinstance(q_str, str) and q_str.strip():
                                tool_label = f"{raw_tool} ({q_str.strip()[:34]})"
                            else:
                                tool_label = str(raw_tool)
                            send({"type": "tool", "name": scrub_secrets(tool_label)})

                    elif event_type == "result":
                        res = evt.get("result") or {}
                        if res.get("conversation_id"):
                            resolved_conv_id = str(res["conversation_id"])
                        if res.get("response"):
                            final_response = str(res["response"])
                        break

                try:
                    proc.wait(timeout=10.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2.0)
            finally:
                stop_watchdog.set()
                self._unregister_proc(proc)
                stderr_thread.join(timeout=1.0)
                if proc.stdout is not None:
                    try:
                        proc.stdout.close()
                    except OSError:
                        pass
                if proc.stderr is not None:
                    try:
                        proc.stderr.close()
                    except OSError:
                        pass

            if self._cancel_requested:
                break

            # Quota maxed on this model -> record it and transparently retry on the next available pool
            stderr_blob = "\n".join(stderr_lines)
            if (
                not final_response
                and not accumulated
                and not timed_out
                and model_failover.is_quota_error(stderr_blob)
                and len(tried_models) < 6
            ):
                tried_models.append(resolved_model)
                nxt = model_failover.next_after_quota(
                    resolved_model, stderr_blob, resolved_effort, tried=tuple(tried_models)
                )
                if nxt:
                    logger.warning("Pocket CLI quota reached on %s; failing over to %s", resolved_model, nxt[0])
                    send(
                        {
                            "type": "tool",
                            "name": f"{model_failover.friendly_name(resolved_model)} quota maxed → switching to {model_failover.friendly_name(nxt[0])}",
                        }
                    )
                    failover_override = nxt
                    continue
                stderr_lines = ["Every model quota is maxed out right now:"] + model_failover.status_lines()

            # Case 1: User sent another message before any mutating tool ran (or tapped Merge Now)
            if self._fold_in_requested:
                folded_notes = self.pop_btw_notes()
                if folded_notes:
                    notes_joined = "\n".join(folded_notes)
                    current_prompt = f"{current_prompt}\n\n[Additional message sent right after]:\n{notes_joined}"
                send({"type": "tool", "name": "Merged your new message into active turn"})
                continue

            pass_text = scrub_secrets((final_response or accumulated).strip())
            if not pass_text:
                if timed_out:
                    pass_text = f"Antigravity CLI timed out after {int(AGY_TIMEOUT_SECONDS)} seconds of inactivity."
                elif stderr_lines:
                    pass_text = scrub_secrets("\n".join(stderr_lines[-8:])).strip()
                else:
                    pass_text = "(No response returned by agy)"

            if not accumulated and pass_text:
                send({"type": "chunk", "text": pass_text})

            if resolved_conv_id:
                active_conv_id = resolved_conv_id
                self.current_conv_id = resolved_conv_id
                if bridging_from_app_id:
                    self.app_conv_bridges[bridging_from_app_id] = resolved_conv_id
                self._persist_runtime_context()

            combined_responses.append(pass_text)

            # Case 2: User sent follow-up message(s) while mutating tools were running — chain automatically!
            followup_notes = self.pop_btw_notes()
            if followup_notes and not timed_out:
                send({"type": "chunk", "text": "\n\n---\n\n"})
                send({"type": "tool", "name": "Continuing with your follow-up message"})
                current_prompt = "\n\n".join(followup_notes)
                continue

            break

        self.cleanup_ephemeral_uploads()
        final_text = "\n\n---\n\n".join(r for r in combined_responses if r).strip()
        if not final_text:
            if self._cancel_requested:
                final_text = "Cancelled active Antigravity CLI turn."
            else:
                final_text = "(No response returned by agy)"

        if first_requested_model and resolved_model != first_requested_model and final_text:
            fo_note = model_failover.failover_note(first_requested_model, resolved_model)
            if fo_note:
                send({"type": "chunk", "text": f"\n\n{fo_note}"})
                final_text = f"{final_text}\n\n{fo_note}"

        receipt = prompt_master.validate_turn_output(
            raw_in,
            mastered,
            final_text,
            channel_name="iphone-cli",
            model=resolved_model,
        )
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        if sync_discord:
            self.sync_turn_to_discord_async(
                mode="agy",
                raw_input=raw_in,
                output_text=final_text,
                duration_ms=elapsed_ms,
                receipt=receipt,
                model=resolved_model,
            )

        try:
            summary = final_text.strip().split("\n")[0].strip()
            if len(summary) > 110:
                summary = summary[:107] + "..."
            push_title = "⚡ MiTH CLI • Turn Complete"
            push_body = f"{summary} ({elapsed_ms / 1000:.1f}s)" if summary else f"Turn finished in {elapsed_ms / 1000:.1f}s"
            self.send_push_notification_async(push_title, push_body, tag=f"turn-{self.current_conv_id[:8]}")
        except Exception:
            pass

        done_payload: dict[str, Any] = {
            "type": "done",
            "mode": "agy",
            "response": final_text,
            "model": resolved_model,
            "conversation_id": self.current_conv_id,
            "receipt": receipt,
            "duration_ms": elapsed_ms,
            "synced_discord": bool(sync_discord),
        }
        send(done_payload)
        return done_payload

    def _resolve_pure_cd(self, cmd_str: str) -> tuple[bool, int, str]:
        """
        Handle pure `cd` / `cd <dir>` cleanly in Python without shell metacharacters.
        Returns `(handled, exit_code, message)`.
        """
        stripped = cmd_str.strip()
        if any(tok in stripped for tok in (";", "&&", "||", "|", "\n", "`", "$(")):
            return False, 0, ""

        if stripped == "cd":
            target_str = "~"
        elif stripped.startswith("cd ") or stripped.startswith("cd\t"):
            target_str = stripped[2:].strip()
            if (
                len(target_str) >= 2
                and target_str[0] == target_str[-1]
                and target_str[0] in ("'", '"')
            ):
                target_str = target_str[1:-1]
        else:
            return False, 0, ""

        if target_str == "-":
            cand = Path(self.previous_cwd).resolve()
        elif target_str.startswith("~"):
            cand = Path(os.path.expanduser(target_str)).resolve()
        else:
            cand = (Path(self.current_cwd) / target_str).resolve()

        if cand.exists() and cand.is_dir():
            self.previous_cwd = self.current_cwd
            self.current_cwd = str(cand)
            self._persist_runtime_context()
            return True, 0, self.current_cwd
        return True, 1, f"cd: no such file or directory: {target_str}"

    def run_shell_turn(
        self,
        cmd_str: str,
        *,
        sync_discord: bool = False,
        emit: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Execute WSL `/bin/bash -lc` command (`shell=False`) with live line streaming & CWD persistence."""
        t0 = time.monotonic()
        send = emit or (lambda _evt: None)
        safe_cmd_display = scrub_secrets(cmd_str)
        send({"type": "shell_start", "cmd": safe_cmd_display, "cwd": self.current_cwd})

        handled_cd, cd_rc, cd_msg = self._resolve_pure_cd(cmd_str)
        if handled_cd:
            stream_kind = "stdout" if cd_rc == 0 else "stderr"
            scrubbed_msg = scrub_secrets(cd_msg)
            send({"type": stream_kind, "line": scrubbed_msg})
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            if sync_discord:
                self.sync_turn_to_discord_async(
                    mode="shell",
                    raw_input=cmd_str,
                    output_text=scrubbed_msg,
                    duration_ms=elapsed_ms,
                    exit_code=cd_rc,
                    cwd=self.current_cwd,
                )
            done_cd: dict[str, Any] = {
                "type": "done",
                "mode": "shell",
                "exit_code": cd_rc,
                "cwd": self.current_cwd,
                "output": scrubbed_msg,
                "duration_ms": elapsed_ms,
                "synced_discord": bool(sync_discord),
            }
            send(done_cd)
            return done_cd

        sentinel = f"__AGY_POCKET_PWD_{secrets.token_hex(8)}__"
        wrapped_script = (
            f"{cmd_str}\n"
            "__agy_rc=$?\n"
            f"printf '\\n{sentinel}:%s\\n' \"$PWD\"\n"
            "exit $__agy_rc"
        )

        env = os.environ.copy()
        for _ek in list(env.keys()):
            if SENSITIVE_ENV_KEY_RE.search(_ek):
                env.pop(_ek, None)
        env["PAGER"] = "cat"
        env["NO_COLOR"] = "1"

        proc = subprocess.Popen(
            ["/bin/bash", "-lc", wrapped_script],
            cwd=self.current_cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            shell=False,
            env=env,
        )
        self._register_proc(proc)

        timed_out = False

        def _timeout_killer() -> None:
            nonlocal timed_out
            if proc.poll() is None:
                timed_out = True
                try:
                    proc.terminate()
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                except OSError:
                    pass

        watchdog = threading.Timer(SHELL_TIMEOUT_SECONDS, _timeout_killer)
        watchdog.daemon = True
        watchdog.start()

        line_queue: queue.Queue[tuple[str, str | None]] = queue.Queue()

        def _pump(pipe: Any, stream_name: str) -> None:
            try:
                for raw_ln in pipe:
                    line_queue.put((stream_name, raw_ln.rstrip("\r\n")))
            except ValueError:
                pass
            finally:
                line_queue.put((stream_name, None))

        assert proc.stdout is not None
        assert proc.stderr is not None
        t_out = threading.Thread(target=_pump, args=(proc.stdout, "stdout"), daemon=True)
        t_err = threading.Thread(target=_pump, args=(proc.stderr, "stderr"), daemon=True)
        t_out.start()
        t_err.start()

        emitted_count = 0
        truncation_notified = False
        collected_lines: list[str] = []
        eof_streams = 0
        held_blank_stdout = False  # blank stdout line that may just be the sentinel's leading newline

        try:
            while eof_streams < 2:
                stream_name, ln = line_queue.get()
                if ln is None:
                    eof_streams += 1
                    continue

                if stream_name == "stdout" and ln.startswith(f"{sentinel}:"):
                    held_blank_stdout = False  # drop the separator newline injected before the sentinel
                    new_pwd = ln.split(":", 1)[1].strip()
                    if new_pwd and Path(new_pwd).is_dir():
                        resolved_pwd = str(Path(new_pwd).resolve())
                        if resolved_pwd != self.current_cwd:
                            self.previous_cwd = self.current_cwd
                            self.current_cwd = resolved_pwd
                            self._persist_runtime_context()
                    continue

                if stream_name == "stdout":
                    if held_blank_stdout:
                        held_blank_stdout = False
                        if emitted_count < MAX_SHELL_STREAM_LINES:
                            send({"type": "stdout", "line": ""})
                            collected_lines.append("")
                            emitted_count += 1
                    if ln == "":
                        held_blank_stdout = True
                        continue

                safe_ln = scrub_secrets(ln)
                if emitted_count < MAX_SHELL_STREAM_LINES:
                    send({"type": stream_name, "line": safe_ln})
                    collected_lines.append(safe_ln)
                    emitted_count += 1
                elif not truncation_notified:
                    trunc_msg = f"... [Output capped at {MAX_SHELL_STREAM_LINES} lines for mobile Safari] ..."
                    send({"type": "stderr", "line": trunc_msg})
                    collected_lines.append(trunc_msg)
                    truncation_notified = True

            rc = proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = proc.wait(timeout=2.0)
        finally:
            watchdog.cancel()
            self._unregister_proc(proc)
            t_out.join(timeout=1.0)
            t_err.join(timeout=1.0)
            if proc.stdout is not None:
                try:
                    proc.stdout.close()
                except OSError:
                    pass
            if proc.stderr is not None:
                try:
                    proc.stderr.close()
                except OSError:
                    pass

        if timed_out:
            timeout_note = "Command timed out after 120 seconds."
            send({"type": "stderr", "line": timeout_note})
            collected_lines.append(timeout_note)
            if rc == 0:
                rc = 124

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        combined_output = "\n".join(collected_lines).strip()

        if sync_discord:
            self.sync_turn_to_discord_async(
                mode="shell",
                raw_input=cmd_str,
                output_text=combined_output,
                duration_ms=elapsed_ms,
                exit_code=rc,
                cwd=self.current_cwd,
            )

        try:
            out_first = (combined_output.strip().split("\n")[0] if combined_output.strip() else f"Exit {rc}").strip()
            if len(out_first) > 110:
                out_first = out_first[:107] + "..."
            push_title = "💻 MiTH CLI • Shell Finished" if rc == 0 else f"❌ MiTH CLI • Shell Exit {rc}"
            push_body = f"$ {cmd_str[:40]} -> {out_first} ({elapsed_ms / 1000:.1f}s)"
            self.send_push_notification_async(push_title, push_body, tag="shell-turn")
        except Exception:
            pass

        done_payload: dict[str, Any] = {
            "type": "done",
            "mode": "shell",
            "exit_code": int(rc),
            "cwd": self.current_cwd,
            "output": combined_output,
            "duration_ms": elapsed_ms,
            "synced_discord": bool(sync_discord),
        }
        send(done_payload)
        return done_payload


class PocketCLIServer(ThreadingHTTPServer):
    """`ThreadingHTTPServer` carrying a dedicated `PocketCLIState` instance."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseHTTPRequestHandler],
        state: PocketCLIState | None = None,
        ui_html_path: Path = UI_HTML_PATH,
        budget_only: bool = False,
    ) -> None:
        host, _port = server_address
        if host != "127.0.0.1":
            raise ValueError(f"OWASP Guardrail: PocketCLIServer MUST bind strictly to 127.0.0.1 (got {host!r})")
        self.state = state or PocketCLIState()
        self.ui_html_path = ui_html_path
        self.budget_only = budget_only
        super().__init__(server_address, RequestHandlerClass)


def _parse_input_shortcuts(raw_input: str, requested_mode: str) -> tuple[str, str, bool]:
    """
    Apply prefix shortcuts:
      - `/clear` or `clear-chat` -> `(mode, "", True)` (is_clear=True)
      - `$ <cmd>` -> `("shell", cmd, False)`
      - `/agy <prompt>` -> `("agy", prompt, False)`
    """
    mode = requested_mode if requested_mode in ("agy", "shell") else "agy"
    if raw_input.strip() in ("/clear", "clear-chat"):
        return mode, "", True
    if raw_input.startswith("$ "):
        return "shell", raw_input[2:].strip(), False
    if raw_input.startswith("/agy "):
        return "agy", raw_input[5:].strip(), False
    return mode, raw_input.strip(), False


class PocketCLIHandler(BaseHTTPRequestHandler):
    """HTTP/1.1 + NDJSON request handler for Antigravity Pocket CLI."""

    protocol_version = "HTTP/1.1"
    server: PocketCLIServer  # type: ignore[assignment]

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.info("%s - %s", self.address_string(), fmt % args)

    _csp_override: str | None = None

    def _add_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "microphone=(self)")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header(
            "Content-Security-Policy",
            self._csp_override
            or "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'",
        )

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str,
        *,
        cache_control: str = "no-store",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache_control)
        self.send_header("Connection", "close")
        self._add_security_headers()
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_json(
        self,
        status: int,
        payload: dict[str, Any],
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(
            status,
            raw,
            "application/json; charset=utf-8",
            cache_control="no-store",
            extra_headers=extra_headers,
        )

    def _read_json_body(self, max_bytes: int = MAX_HTTP_BODY_BYTES) -> dict[str, Any] | None:
        length_str = self.headers.get("Content-Length") or "0"
        try:
            length = int(length_str)
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid Content-Length."})
            return None

        if length < 0 or length > max_bytes:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"ok": False, "error": f"Request body exceeds {max_bytes} bytes."},
            )
            return None

        if length == 0:
            return {}

        raw_bytes = self.rfile.read(length)
        try:
            parsed = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Malformed JSON body."})
            return None

        if not isinstance(parsed, dict):
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "JSON body must be an object."})
            return None
        return parsed

    def _require_auth(self, *, bearer_only: bool = False) -> bool:
        auth_hdr = self.headers.get("Authorization") or ""
        has_bearer = auth_hdr.strip().lower().startswith("bearer ")
        if not has_bearer:
            sec_fetch = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
            if sec_fetch == "cross-site":
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"ok": False, "error": "Cross-site cookie requests are blocked (CSRF protection)."},
                )
                return False

        if bearer_only:
            parts = auth_hdr.strip().split(None, 1)
            tok = parts[1].strip() if (len(parts) == 2 and parts[0].lower() == "bearer") else None
        else:
            tok = extract_session_token(self.headers)

        if not self.server.state.verify_session_token(tok):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"ok": False, "error": "Unauthorized. Authenticate with your 6-digit Discord PIN."},
            )
            return False
        return True

    def do_HEAD(self) -> None:
        self.close_connection = True
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self._add_security_headers()
        self.end_headers()

    def _serve_budget_only_get(self, path: str) -> None:
        """Dedicated budget origin: only the PIN-gated budget app, its manifest and icons."""
        if path == "/manifest.json":
            self._send_bytes(
                HTTPStatus.OK,
                json.dumps(BUDGET_MANIFEST).encode("utf-8"),
                "application/manifest+json; charset=utf-8",
                cache_control="no-cache",
            )
            return
        if path in ("/icon-512.png", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"):
            icon = BUDGET_ICON_512_PATH if path == "/icon-512.png" else BUDGET_ICON_180_PATH
            if icon.is_file():
                self._send_bytes(HTTPStatus.OK, icon.read_bytes(), "image/png", cache_control="no-cache")
            else:
                self._send_bytes(HTTPStatus.NOT_FOUND, b"", "text/plain; charset=utf-8")
            return
        tok = extract_session_token(self.headers)
        if not self.server.state.verify_session_token(tok):
            self._send_bytes(HTTPStatus.UNAUTHORIZED, BUDGET_LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        budget_path = getattr(self.server, "budget_html_path", BUDGET_HTML_PATH)
        if not budget_path.exists():
            self._send_bytes(HTTPStatus.NOT_FOUND, b"budget-tool.html not found.", "text/plain; charset=utf-8")
            return
        html = budget_path.read_text(encoding="utf-8").replace("<head>", "<head>" + BUDGET_HEAD_INJECT, 1)
        self._csp_override = BUDGET_CSP
        self._send_bytes(HTTPStatus.OK, html.encode("utf-8"), "text/html; charset=utf-8", cache_control="no-store")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if getattr(self.server, "budget_only", False):
            if path in BUDGET_ONLY_GET:
                self._serve_budget_only_get(path)
            else:
                self._send_bytes(HTTPStatus.NOT_FOUND, b"Not found.", "text/plain; charset=utf-8")
            return

        if path in ("/", "/index.html", "/cli"):
            ui_path = self.server.ui_html_path
            if ui_path.exists():
                html_bytes = ui_path.read_bytes()
                self._send_bytes(
                    HTTPStatus.OK,
                    html_bytes,
                    "text/html; charset=utf-8",
                    cache_control="no-store",
                )
            else:
                fallback = (
                    "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
                    "<title>Antigravity Pocket CLI</title></head>"
                    "<body style='background:#09090B;color:#F4F4F5;font-family:monospace;padding:24px'>"
                    "pocket_cli_ui.html not found.</body></html>"
                ).encode("utf-8")
                self._send_bytes(
                    HTTPStatus.NOT_FOUND,
                    fallback,
                    "text/html; charset=utf-8",
                    cache_control="no-store",
                )
            return

        if path == "/budget":
            tok = extract_session_token(self.headers)
            if not self.server.state.verify_session_token(tok):
                self._send_bytes(
                    HTTPStatus.UNAUTHORIZED,
                    (
                        "<!doctype html><meta name='viewport' content='width=device-width,initial-scale=1'>"
                        "<body style='background:#09090B;color:#F4F4F5;font-family:system-ui;padding:24px'>"
                        "Sign in first: open <a style='color:#818cf8' href='/cli'>/cli</a>, "
                        "connect, then return to /budget.</body>"
                    ).encode("utf-8"),
                    "text/html; charset=utf-8",
                )
                return
            budget_path = getattr(self.server, "budget_html_path", BUDGET_HTML_PATH)
            if not budget_path.exists():
                self._send_bytes(HTTPStatus.NOT_FOUND, b"budget-tool.html not found.", "text/plain; charset=utf-8")
                return
            self._csp_override = BUDGET_CSP
            self._send_bytes(
                HTTPStatus.OK,
                budget_path.read_bytes(),
                "text/html; charset=utf-8",
                cache_control="no-store",
            )
            return

        if path == "/manifest.json":
            self._send_bytes(
                HTTPStatus.OK,
                json.dumps(PWA_MANIFEST, indent=2).encode("utf-8"),
                "application/manifest+json; charset=utf-8",
                cache_control="no-cache",
            )
            return

        if path == "/sw.js":
            self._send_bytes(
                HTTPStatus.OK,
                SW_JS.encode("utf-8"),
                "application/javascript; charset=utf-8",
                cache_control="no-cache, no-store, must-revalidate",
                extra_headers={"Service-Worker-Allowed": "/"},
            )
            return

        if path == "/api/push/public-key":
            try:
                pub_key, _ = self.server.state.get_or_create_vapid()
            except ImportError:
                self._send_json(
                    HTTPStatus.NOT_IMPLEMENTED,
                    {"ok": False, "error": "Push alerts need the optional 'pywebpush' package (pip install pywebpush)."},
                )
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "publicKey": pub_key})
            return

        if path == "/icon.svg":
            self._send_bytes(
                HTTPStatus.OK,
                ICON_SVG.encode("utf-8"),
                "image/svg+xml; charset=utf-8",
                cache_control="no-cache",
            )
            return

        if path in ("/apple-touch-icon.png", "/apple-touch-icon-precomposed.png", "/icon-512.png"):
            icon_file = ICON_512_PATH if path == "/icon-512.png" else ICON_180_PATH
            if not icon_file.is_file() and ICON_512_PATH.is_file():
                icon_file = ICON_512_PATH
            if icon_file.is_file():
                self._send_bytes(
                    HTTPStatus.OK,
                    icon_file.read_bytes(),
                    "image/png",
                    cache_control="no-cache",
                )
            else:
                self._send_bytes(
                    HTTPStatus.OK,
                    ICON_SVG.encode("utf-8"),
                    "image/svg+xml; charset=utf-8",
                    cache_control="no-cache",
                )
            return

        if path == "/api/conversations":
            if not self._require_auth():
                return
            convs = list_antigravity_conversations(limit_per_source=18)
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "active_conversation_id": self.server.state.current_conv_id,
                    "conversations": convs,
                },
            )
            return

        if path == "/api/conversations/history":
            if not self._require_auth():
                return
            qs = parse_qs(urlparse(self.path).query)
            cid = (qs.get("id") or [""])[0].strip()
            src = (qs.get("source") or ["cli"])[0].strip().lower()
            turns = load_conversation_transcript(cid, source=src, max_turns=20)
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "conversation_id": cid,
                    "source": src,
                    "turns": turns,
                },
            )
            return

        if path == "/api/health":
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "service": "agy-pocket-cli",
                    "port": int(self.server.server_port),
                },
            )
            return

        if path == "/api/auth/status":
            tok = extract_session_token(self.headers)
            authed = self.server.state.verify_session_token(tok)
            self._send_json(
                HTTPStatus.OK,
                {
                    "authenticated": authed,
                    "cwd": self.server.state.current_cwd,
                    "tunnel_url": self.server.state.read_tunnel_url(),
                    "discord_channel": IPHONE_CLI_CHANNEL_DISPLAY,
                    "conversation_id": self.server.state.current_conv_id if authed else "",
                    "turn_in_progress": bool(self.server.state.turn_in_progress) if authed else False,
                    "turn_id": int(self.server.state.turn_id) if authed else 0,
                },
            )
            return

        if path == "/api/last-turn":
            if not self._require_auth():
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "turn_id": self.server.state.turn_id,
                    "in_progress": bool(self.server.state.turn_in_progress),
                    "prompt": self.server.state.live_prompt,
                    "mode": self.server.state.live_mode,
                    "started_at": self.server.state.live_started_at,
                    "conversation_id": self.server.state.current_conv_id,
                    "enhanced": self.server.state.live_enhanced,
                    "tools": list(self.server.state.live_tools),
                    "partial_text": self.server.state.live_text,
                    "last_turn": self.server.state.last_turn_result,
                },
            )
            return

        if path == "/api/audio/list":
            if not self._require_auth():
                return
            tracks: list[dict[str, Any]] = []
            music_root = Path("~/Music")
            # Strictly curated: Final EQed Masters, Final EQed Originals, and "Success Isn't Gold" Album
            studio_roots: list[tuple[int, str, Path, bool]] = [
                (0, "Final EQ Masters", music_root / "01_Masters", False),
                (1, "Final EQ Originals", music_root / "01_Masters" / "02_Singles_Final_EQ", False),
                (2, "Success Isn't Gold", music_root / "02_Original_Song_Mixes" / "03_Success_Isnt_Gold_Album", False),
            ]
            seen_paths: set[str] = set()
            seen_stems: set[str] = set()
            candidates: list[tuple[int, int, str, str, Path, float]] = []
            for cat_rank, category_label, sroot, recursive in studio_roots:
                try:
                    if not sroot.is_dir():
                        continue
                except OSError:
                    continue
                try:
                    iterator = sroot.rglob("*") if recursive else sroot.iterdir()
                    files_in_dir = [p for p in iterator if p.is_file()]
                    # Sort MP3s before WAVs so deduplication always picks the fast-streaming 320k MP3
                    files_in_dir.sort(key=lambda f: (0 if f.suffix.lower() == ".mp3" else 1, f.name.lower()))
                    for p in files_in_dir:
                        try:
                            ext = p.suffix.lower()
                            if ext not in AUDIO_EXT_MIME:
                                continue
                            raw_str = str(p)
                            if raw_str in seen_paths or "/.ephemeral/" in raw_str:
                                continue
                            stem_key = re.sub(
                                r"(_mith_autoeq_320k|_mith_autoeq|_mith_eq_audio|_mith_eq|_ep_master_locked|_promo1|\s+)+$",
                                "",
                                p.stem.lower().strip(),
                            )
                            if stem_key in seen_stems:
                                continue
                            st = p.stat()
                            if st.st_size <= 0:
                                continue
                            seen_paths.add(raw_str)
                            seen_stems.add(stem_key)
                            is_mp3 = 0 if ext == ".mp3" else 1
                            sz_mb = round(st.st_size / (1024 * 1024), 2)
                            candidates.append(
                                (cat_rank, is_mp3, p.name.lower(), category_label, p, sz_mb)
                            )
                        except OSError:
                            continue
                except OSError:
                    continue
            candidates.sort(key=lambda item: (item[0], item[2]))
            for _, _, _, category_label, p, sz_mb in candidates[:60]:
                tracks.append(
                    {
                        "name": p.name,
                        "category": category_label,
                        "folder": p.parent.name,
                        "path": str(p),
                        "ext": p.suffix.lower().lstrip(".").upper(),
                        "size_mb": sz_mb,
                    }
                )
            self._send_json(HTTPStatus.OK, {"ok": True, "tracks": tracks})
            return

        if path == "/api/audio":
            parsed_url = urlparse(self.path)
            qs = parse_qs(parsed_url.query)
            q_tok = (qs.get("token") or [""])[0].strip()
            tok = q_tok or extract_session_token(self.headers)
            if not self.server.state.verify_session_token(tok):
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Unauthorized audio stream."})
                return

            raw_audio_path = (qs.get("path") or [""])[0].strip()
            if not raw_audio_path:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Missing 'path' query parameter."})
                return

            if raw_audio_path.startswith("file://"):
                raw_audio_path = raw_audio_path[len("file://") :]

            try:
                target_file = Path(raw_audio_path).resolve()
            except OSError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid audio path."})
                return

            ext = target_file.suffix.lower()
            mime = AUDIO_EXT_MIME.get(ext)
            if not mime:
                self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Unsupported audio file extension."})
                return

            allowed = False
            for root in ALLOWED_AUDIO_ROOTS:
                try:
                    if target_file.is_relative_to(root.resolve()):
                        allowed = True
                        break
                except (OSError, ValueError):
                    continue

            if not allowed or not target_file.is_file():
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Audio file not found."})
                return

            try:
                total_size = target_file.stat().st_size
            except OSError:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Unable to stat audio file."})
                return

            range_hdr = (self.headers.get("Range") or "").strip()
            start_byte = 0
            end_byte = max(0, total_size - 1)
            is_partial = False

            if range_hdr.lower().startswith("bytes=") and total_size > 0:
                range_spec = range_hdr[6:].split(",", 1)[0].strip()
                if "-" in range_spec:
                    s_part, e_part = range_spec.split("-", 1)
                    try:
                        if s_part.strip():
                            start_byte = int(s_part.strip())
                            if e_part.strip():
                                end_byte = min(total_size - 1, int(e_part.strip()))
                        elif e_part.strip():
                            suffix_len = int(e_part.strip())
                            start_byte = max(0, total_size - suffix_len)
                        if 0 <= start_byte <= end_byte < total_size:
                            is_partial = True
                    except ValueError:
                        pass

            chunk_len = (end_byte - start_byte + 1) if total_size > 0 else 0
            self.close_connection = True
            self.send_response(HTTPStatus.PARTIAL_CONTENT if is_partial else HTTPStatus.OK)
            self.send_header("Content-Type", mime)
            self.send_header("Accept-Ranges", "bytes")
            if is_partial:
                self.send_header("Content-Range", f"bytes {start_byte}-{end_byte}/{total_size}")
            self.send_header("Content-Length", str(chunk_len))
            self.send_header("Cache-Control", "private, max-age=300")
            self.send_header("Connection", "close")
            self._add_security_headers()
            self.end_headers()

            if chunk_len > 0:
                try:
                    with target_file.open("rb") as af:
                        af.seek(start_byte)
                        remaining = chunk_len
                        while remaining > 0:
                            buf = af.read(min(65536, remaining))
                            if not buf:
                                break
                            self.wfile.write(buf)
                            remaining -= len(buf)
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found."})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        state = self.server.state
        if getattr(self.server, "budget_only", False) and path not in BUDGET_ONLY_POST:
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found."})
            return

        if path == "/api/auth/direct":
            client_ip = self.client_address[0] if self.client_address else ""
            host_hdr = (self.headers.get("Host") or "").strip().lower()
            ts_user = self.headers.get("Tailscale-User-Login")
            xff = (self.headers.get("X-Forwarded-For") or "").strip()
            cf_ip = (self.headers.get("Cf-Connecting-Ip") or "").strip()

            # Block passwordless direct connect if request came over a public internet tunnel
            is_public_tunnel = bool(cf_ip) or ("trycloudflare.com" in host_hdr) or (
                bool(xff) and not xff.startswith(("127.", "100.", "::1"))
            )
            is_trusted = (not is_public_tunnel) and (
                client_ip in ("127.0.0.1", "::1", "localhost")
                or "ts.net" in host_hdr
                or bool(ts_user)
                or client_ip.startswith("100.")
            )

            if not is_trusted:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"ok": False, "error": "Public tunnel requires your PIN or 6-digit Discord code."},
                )
                return

            tok = state.mint_direct_session_token()
            cookie = (
                f"agy_pocket_session={tok}; Path=/; Max-Age={SESSION_TTL_SECONDS}; "
                "HttpOnly; SameSite=Strict"
            )
            forwarded_proto = (self.headers.get("X-Forwarded-Proto") or "").strip().lower()
            if forwarded_proto == "https":
                cookie += "; Secure"

            self._send_json(
                HTTPStatus.OK,
                {"ok": True, "session_token": tok, "cwd": state.current_cwd},
                extra_headers={"Set-Cookie": cookie},
            )
            return

        if path == "/api/auth/request-code":
            # Drain optional body if sent
            if (self.headers.get("Content-Length") or "0") != "0":
                if self._read_json_body() is None:
                    return

            allowed, code_or_err, ttl_or_retry = state.create_pairing_code()
            if not allowed:
                self._send_json(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"ok": False, "error": code_or_err, "retry_after": ttl_or_retry},
                )
                return

            try:
                state.send_pairing_code_to_discord(code_or_err)
            except Exception as exc:
                state.invalidate_active_pin()
                logger.error("Failed posting pairing PIN to Discord: %s", scrub_secrets(str(exc)))
                self._send_json(
                    HTTPStatus.BAD_GATEWAY,
                    {"ok": False, "error": "Failed delivering pairing PIN to Discord #iphone-cli."},
                )
                return

            self._send_json(HTTPStatus.OK, {"ok": True, "expires_in": ttl_or_retry})
            return

        if path == "/api/auth/verify-code":
            body = self._read_json_body()
            if body is None:
                return
            submitted = str(body.get("code") or "").strip()
            ok, tok_or_err, remaining = state.verify_pairing_code(submitted)
            if not ok:
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"ok": False, "error": tok_or_err, "attempts_remaining": remaining},
                )
                return

            cookie = (
                f"agy_pocket_session={tok_or_err}; Path=/; Max-Age={SESSION_TTL_SECONDS}; "
                "HttpOnly; SameSite=Strict"
            )
            forwarded_proto = (self.headers.get("X-Forwarded-Proto") or "").strip().lower()
            if forwarded_proto == "https":
                cookie += "; Secure"

            self._send_json(
                HTTPStatus.OK,
                {"ok": True, "session_token": tok_or_err, "cwd": state.current_cwd},
                extra_headers={"Set-Cookie": cookie},
            )
            return

        if path == "/api/auth/login":
            length_str = self.headers.get("Content-Length") or "0"
            try:
                length = int(length_str)
            except ValueError:
                length = 0
            if length < 0 or length > MAX_HTTP_BODY_BYTES:
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"ok": False, "error": "Payload too large."})
                return
            raw_form = self.rfile.read(length).decode("utf-8", errors="ignore") if length > 0 else ""
            form_data = parse_qs(raw_form, keep_blank_values=True)
            submitted = (
                (form_data.get("password") or form_data.get("code") or [""])[0]
            ).strip()
            ok, tok_or_err, remaining = state.verify_pairing_code(submitted)
            if not ok:
                from urllib.parse import quote
                err_msg = tok_or_err
                if remaining > 0:
                    err_msg = f"{tok_or_err} ({remaining} attempts left)"
                redirect_html = (
                    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
                    "<title>MiTH CLI</title></head><body style='background:#09090B;'>"
                    f"<script>window.location.replace('/cli?auth_error={quote(err_msg)}');</script>"
                    "</body></html>"
                ).encode("utf-8")
                self._send_bytes(
                    HTTPStatus.OK,
                    redirect_html,
                    "text/html; charset=utf-8",
                    cache_control="no-store",
                )
                return

            cookie = (
                f"agy_pocket_session={tok_or_err}; Path=/; Max-Age={SESSION_TTL_SECONDS}; "
                "HttpOnly; SameSite=Strict"
            )
            forwarded_proto = (self.headers.get("X-Forwarded-Proto") or "").strip().lower()
            if forwarded_proto == "https":
                cookie += "; Secure"

            success_html = (
                "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
                "<title>MiTH CLI</title></head><body style='background:#09090B;'>"
                "<script>"
                f"try {{ localStorage.setItem('agy_pocket_token_v2', {json.dumps(tok_or_err)}); }} catch (_) {{}}"
                "window.location.replace('/cli');"
                "</script></body></html>"
            ).encode("utf-8")
            self._send_bytes(
                HTTPStatus.OK,
                success_html,
                "text/html; charset=utf-8",
                cache_control="no-store",
                extra_headers={"Set-Cookie": cookie},
            )
            return

        if path == "/api/auth/logout":
            if (self.headers.get("Content-Length") or "0") != "0":
                try:
                    n = min(int(self.headers.get("Content-Length") or "0"), MAX_HTTP_BODY_BYTES)
                    if n > 0:
                        self.rfile.read(n)
                except ValueError:
                    pass
            clear_cookie = "agy_pocket_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
            self._send_json(
                HTTPStatus.OK,
                {"ok": True},
                extra_headers={"Set-Cookie": clear_cookie},
            )
            return

        if path == "/api/upload":
            if not self._require_auth():
                return
            body = self._read_json_body(max_bytes=MAX_UPLOAD_BODY_BYTES)
            if body is None:
                return
            raw_name = str(body.get("filename") or "iphone_photo.jpg").strip()
            b64_data = str(body.get("data_base64") or "").strip()
            if not b64_data:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Missing 'data_base64' payload."})
                return
            if "," in b64_data and b64_data.lower().startswith("data:"):
                b64_data = b64_data.split(",", 1)[1].strip()
            try:
                file_bytes = base64.b64decode(b64_data, validate=False)
            except Exception:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid base64 encoding."})
                return
            if not file_bytes:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Decoded file is empty."})
                return

            base_name = Path(raw_name).name
            safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", base_name).strip("._") or "iphone_upload.jpg"
            ts_prefix = time.strftime("%Y%m%d_%H%M%S")
            stamped_name = f"{ts_prefix}_{safe_name}"
            keep_file = bool(body.get("keep", False))

            cwd_path = Path(state.current_cwd)
            base_uploads = (cwd_path / "workspace" / "uploads") if (cwd_path / "workspace").exists() else UPLOADS_DIR
            upload_root = base_uploads if keep_file else (base_uploads / ".ephemeral")
            upload_root.mkdir(parents=True, exist_ok=True)
            saved_path = (upload_root / stamped_name).resolve()
            saved_path.write_bytes(file_bytes)

            win_copy_str = ""
            if keep_file:
                try:
                    if DOCUMENTS_UPLOADS_DIR.parent.exists():
                        DOCUMENTS_UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
                        doc_target = DOCUMENTS_UPLOADS_DIR / stamped_name
                        doc_target.write_bytes(file_bytes)
                        win_copy_str = f"./workspace/uploads/iphone\\{stamped_name}"
                except OSError:
                    pass
            else:
                state.register_ephemeral_upload(saved_path)

            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "filename": stamped_name,
                    "path": str(saved_path),
                    "windows_path": win_copy_str,
                    "ephemeral": not keep_file,
                    "size_bytes": len(file_bytes),
                },
            )
            return

        if path == "/api/push/subscribe":
            if not self._require_auth():
                return
            body = self._read_json_body()
            if body is None:
                return
            sub = body.get("subscription")
            if not isinstance(sub, dict) or not sub.get("endpoint"):
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid subscription object."})
                return
            state.save_push_subscription(sub)
            state.send_push_notification_async(
                "🔔 MiTH CLI Alerts Armed",
                "Lock Screen notifications are active. You'll receive alerts when commands finish.",
                tag="welcome",
            )
            self._send_json(HTTPStatus.OK, {"ok": True, "subscribed": True})
            return

        if path == "/api/push/unsubscribe":
            if not self._require_auth():
                return
            body = self._read_json_body()
            if body is None:
                return
            endpoint = str(body.get("endpoint") or "").strip()
            if endpoint:
                state.remove_push_subscription(endpoint)
            self._send_json(HTTPStatus.OK, {"ok": True, "subscribed": False})
            return

        if path == "/api/push/test":
            if not self._require_auth():
                return
            state.send_push_notification_async(
                "⚡ MiTH CLI • Test Alert",
                "Lock Screen notifications are functioning perfectly!",
                tag="test",
            )
            self._send_json(HTTPStatus.OK, {"ok": True, "sent": True})
            return

        if path == "/api/cancel":
            if not self._require_auth():
                return
            if (self.headers.get("Content-Length") or "0") != "0":
                if self._read_json_body() is None:
                    return
            cancelled = state.cancel_active_process()
            self._send_json(HTTPStatus.OK, {"ok": True, "cancelled": cancelled})
            return

        if path == "/api/clear":
            if not self._require_auth():
                return
            if (self.headers.get("Content-Length") or "0") != "0":
                if self._read_json_body() is None:
                    return
            state.clear_conversation()
            self._send_json(HTTPStatus.OK, {"ok": True})
            return

        if path == "/api/conversations/select":
            if not self._require_auth():
                return
            body = self._read_json_body()
            if body is None:
                return
            cid = str(body.get("conversation_id") or "").strip()
            if cid and not _CONV_ID_RE.match(cid):
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid conversation_id."})
                return
            state.current_conv_id = cid
            state._persist_runtime_context()
            self._send_json(HTTPStatus.OK, {"ok": True, "conversation_id": cid})
            return

        if path == "/api/btw":
            if not self._require_auth():
                return
            body = self._read_json_body()
            if body is None:
                return
            note_text = str(body.get("text") or "").strip()
            steer_now = bool(body.get("steer", False))
            if not note_text and not steer_now:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Missing 'text' for follow-up message."})
                return
            if not state.turn_in_progress:
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "queued_count": 0,
                        "folded_immediately": False,
                        "turn_already_finished": True,
                    },
                )
                return
            queued_count = state.queue_btw_note(note_text) if note_text else len(state.btw_notes)
            should_fold_now = steer_now or (not state.active_turn_mutated)
            folded = state.request_fold_in() if should_fold_now else False
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "queued_count": queued_count,
                    "steered": steer_now,
                    "folded_immediately": folded,
                    "turn_already_finished": False,
                },
            )
            return

        if path == "/api/run":
            if not self._require_auth():
                return
            body = self._read_json_body()
            if body is None:
                return

            raw_input = body.get("input")
            if not isinstance(raw_input, str) or not raw_input.strip():
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Non-empty 'input' is required."})
                return
            if len(raw_input) > MAX_INPUT_CHARS:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"ok": False, "error": f"Input exceeds maximum length of {MAX_INPUT_CHARS} characters."},
                )
                return

            req_mode = str(body.get("mode") or "agy").strip().lower()
            if req_mode not in ("agy", "shell"):
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid mode (must be 'agy' or 'shell')."})
                return

            enhance = bool(body.get("enhance", DEFAULT_ENHANCE))
            sync_discord = bool(body.get("sync_discord", False))
            req_model = str(body.get("model") or "auto").strip() or "auto"
            has_conv_override = "conversation_id" in body
            req_conv_id = str(body.get("conversation_id") or "").strip() if has_conv_override else None
            if req_conv_id and not _CONV_ID_RE.match(req_conv_id):
                req_conv_id = ""
            req_conv_source = str(body.get("conv_source") or "cli").strip().lower() or "cli"

            effective_mode, effective_input, is_clear = _parse_input_shortcuts(raw_input, req_mode)
            if not is_clear and not effective_input:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Command input cannot be empty."})
                return

            # Begin live NDJSON stream
            self.close_connection = True
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "close")
            self._add_security_headers()
            self.end_headers()

            stream_alive = True
            write_lock = threading.Lock()
            stop_heartbeat = threading.Event()
            state.turn_id += 1
            state.last_turn_result = None
            state.live_prompt = effective_input
            state.live_mode = effective_mode
            state.live_started_at = time.time()
            state.live_enhanced = None
            state.live_tools = []
            state.live_text = ""

            def emit_ndjson(event_obj: dict[str, Any]) -> None:
                nonlocal stream_alive
                ev_type = event_obj.get("type")
                if ev_type == "enhanced":
                    state.live_enhanced = event_obj
                elif ev_type == "tool":
                    state.live_tools.append(str(event_obj.get("name") or "tool"))
                elif ev_type == "chunk":
                    state.live_text += str(event_obj.get("text") or "")
                elif ev_type in ("stdout", "stderr"):
                    ln_str = str(event_obj.get("line") or "")
                    state.live_text += (ln_str + "\n")
                elif ev_type == "done":
                    event_obj["turn_id"] = state.turn_id
                    state.last_turn_result = event_obj
                if not stream_alive:
                    return
                with write_lock:
                    if not stream_alive:
                        return
                    try:
                        encoded = (json.dumps(event_obj, ensure_ascii=False) + "\n").encode("utf-8")
                        self.wfile.write(encoded)
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        stream_alive = False

            if is_clear:
                state.clear_conversation()
                emit_ndjson(
                    {
                        "type": "done",
                        "mode": effective_mode,
                        "response": "Conversation cleared.",
                        "conversation_id": "",
                        "cwd": state.current_cwd,
                        "duration_ms": 0,
                        "synced_discord": False,
                    }
                )
                return

            def _heartbeat_loop() -> None:
                while not stop_heartbeat.wait(2.0):
                    if not stream_alive:
                        break
                    emit_ndjson({"type": "ping", "ts": int(time.time())})

            hb_thread = threading.Thread(target=_heartbeat_loop, name="ndjson-heartbeat", daemon=True)
            state.turn_in_progress = True
            hb_thread.start()

            try:
                if effective_mode == "agy":
                    state.run_agy_turn(
                        effective_input,
                        enhance=enhance,
                        sync_discord=sync_discord,
                        requested_model=req_model,
                        target_conv_id=req_conv_id,
                        conv_source=req_conv_source,
                        emit=emit_ndjson,
                    )
                else:
                    state.run_shell_turn(
                        effective_input,
                        sync_discord=sync_discord,
                        emit=emit_ndjson,
                    )
            except Exception as exc:
                safe_err = scrub_secrets(str(exc))
                logger.exception("Error during /api/run (%s): %s", effective_mode, safe_err)
                if isinstance(exc, FileNotFoundError) and effective_mode == "agy":
                    # Most common first-run failure on a fresh install: the AI CLI isn't installed / on PATH.
                    safe_err = (
                        f"AI CLI not found ('{state.agy_bin_path}'). Install the Antigravity `agy` CLI and sign in, "
                        "or set AGY_BIN_PATH in .env. Shell mode (start a message with `$`) works without it."
                    )
                emit_ndjson({"type": "error", "error": safe_err})
                emit_ndjson(
                    {
                        "type": "done",
                        "mode": effective_mode,
                        "response": f"Error: {safe_err}",
                        "exit_code": 1,
                        "cwd": state.current_cwd,
                        "duration_ms": 0,
                        "synced_discord": False,
                    }
                )
            finally:
                stop_heartbeat.set()
                state.turn_in_progress = False
            return

        if path == "/api/webhook":
            if not self._require_auth(bearer_only=True):
                return
            body = self._read_json_body()
            if body is None:
                return

            raw_input = body.get("input")
            if not isinstance(raw_input, str) or not raw_input.strip():
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Non-empty 'input' is required."})
                return
            if len(raw_input) > MAX_INPUT_CHARS:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"ok": False, "error": f"Input exceeds maximum length of {MAX_INPUT_CHARS} characters."},
                )
                return

            req_mode = str(body.get("mode") or "agy").strip().lower()
            if req_mode not in ("agy", "shell"):
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid mode."})
                return

            enhance = bool(body.get("enhance", DEFAULT_ENHANCE))
            req_model = str(body.get("model") or "auto").strip() or "auto"
            effective_mode, effective_input, is_clear = _parse_input_shortcuts(raw_input, req_mode)

            if is_clear:
                state.clear_conversation()
                self._send_json(
                    HTTPStatus.OK,
                    {"ok": True, "mode": effective_mode, "output": "Conversation cleared.", "receipt": None},
                )
                return

            if not effective_input:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Command input cannot be empty."})
                return

            try:
                if effective_mode == "agy":
                    done = state.run_agy_turn(
                        effective_input,
                        enhance=enhance,
                        sync_discord=True,
                        requested_model=req_model,
                    )
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "ok": True,
                            "mode": "agy",
                            "output": done.get("response", ""),
                            "receipt": done.get("receipt"),
                            "conversation_id": done.get("conversation_id", ""),
                        },
                    )
                else:
                    done = state.run_shell_turn(effective_input, sync_discord=True)
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "ok": True,
                            "mode": "shell",
                            "output": done.get("output", ""),
                            "exit_code": done.get("exit_code", 0),
                            "cwd": done.get("cwd", state.current_cwd),
                            "receipt": None,
                        },
                    )
            except Exception as exc:
                safe_err = scrub_secrets(str(exc))
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": safe_err})
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found."})


def create_server(
    port: int = PORT,
    state: PocketCLIState | None = None,
    ui_html_path: Path = UI_HTML_PATH,
    budget_only: bool = False,
) -> PocketCLIServer:
    """Create a strictly loopback-bound (`127.0.0.1`) `PocketCLIServer` instance."""
    return PocketCLIServer(
        (BIND_HOST, port), PocketCLIHandler, state=state, ui_html_path=ui_html_path, budget_only=budget_only
    )


def main() -> None:
    server = create_server(port=PORT)
    logger.info("Antigravity Pocket CLI listening strictly on http://%s:%d", BIND_HOST, PORT)

    # Dedicated budget-only origin (shares the PIN/session state, serves nothing else).
    budget_server: PocketCLIServer | None = None
    try:
        budget_server = create_server(port=BUDGET_PORT, state=server.state, budget_only=True)
        threading.Thread(target=budget_server.serve_forever, daemon=True).start()
        logger.info("Budget app listening strictly on http://%s:%d (budget-only)", BIND_HOST, BUDGET_PORT)
    except OSError as exc:
        logger.error("Budget listener failed to start on %d: %s", BUDGET_PORT, exc)

    def _shutdown_handler(signum: int, _frame: Any) -> None:
        logger.info("Received signal %d — shutting down Pocket CLI server...", signum)
        server.state.cancel_active_process()
        threading.Thread(target=server.shutdown, daemon=True).start()
        if budget_server is not None:
            threading.Thread(target=budget_server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)

    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
