"""
Shared model failover / quota manager for the MiTH Discord bridge (`bot.py`)
and the MiTH-CLI Pocket server (`pocket_cli_server.py`).

When `agy` returns `RESOURCE_EXHAUSTED (code 429): Individual quota reached ...
Resets in 68h27m38s`, the exhausted model *family* (gemini / claude / gpt-oss)
is put on cooldown in a shared JSON state file until the reported reset time.
Every caller then asks `pick_available()` / `next_after_quota()` for the best
model that is still usable, so Discord and MiTH-CLI both keep working on
whatever quota pool is left.

CLI:
    python model_failover.py status
    python model_failover.py chain gemini-4-argon-medium
    python model_failover.py clear [family]
    python model_failover.py selftest
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

BRIDGE_DIR = Path(__file__).resolve().parent
STATE_PATH = Path(
    os.getenv("MODEL_QUOTA_STATE_PATH", str(BRIDGE_DIR / "workspace" / ".model_quota_state.json"))
)
DEFAULT_COOLDOWN_SECONDS = int(os.getenv("MODEL_QUOTA_DEFAULT_COOLDOWN", "900"))  # 15 min if no reset time given
_EFFORTS = ("low", "medium", "high", "xhigh", "max")
_LOCK = threading.Lock()

# Models verified via `agy models` (2026-10-24).
FAMILY_MODELS: dict[str, dict[str, str]] = {
    "gemini-argon": {"low": "gemini-4-argon-low", "medium": "gemini-4-argon-medium", "high": "gemini-4-argon-high"},
    "gemini-flash": {"low": "gemini-3.8-flash-low", "medium": "gemini-3.8-flash-medium", "high": "gemini-3.8-flash-high"},
    "claude-opus": {"low": "claude-opus-5-5-low", "medium": "claude-opus-5-5-medium", "high": "claude-opus-5-5-high"},
    "claude-sonnet": {"low": "claude-sonnet-5-5-low", "medium": "claude-sonnet-5-5-medium", "high": "claude-sonnet-5-5-high"},
    "gpt-oss": {"low": "gpt-oss-120b-medium", "medium": "gpt-oss-120b-medium", "high": "gpt-oss-120b-medium"},
}

# Ordered fallback preference per requested family (closest capability first).
FALLBACK_ORDER: dict[str, tuple[str, ...]] = {
    "gemini-flash": ("gemini-flash", "claude-sonnet", "gpt-oss", "gemini-argon", "claude-opus"),
    "gemini-argon": ("gemini-argon", "claude-sonnet", "claude-opus", "gpt-oss", "gemini-flash"),
    "claude-opus": ("claude-opus", "gemini-argon", "claude-sonnet", "gpt-oss", "gemini-flash"),
    "claude-sonnet": ("claude-sonnet", "gemini-argon", "claude-opus", "gpt-oss", "gemini-flash"),
    "gpt-oss": ("gpt-oss", "claude-sonnet", "gemini-flash", "gemini-argon", "claude-opus"),
}

FRIENDLY: dict[str, str] = {
    "gemini-argon": "Gemini 4 Argon",
    "gemini-flash": "Gemini 3.8 Flash",
    "claude-opus": "Claude Opus 5.5",
    "claude-sonnet": "Claude Sonnet 5.5",
    "gpt-oss": "GPT-OSS 120B",
}

_QUOTA_RE = re.compile(
    r"RESOURCE_EXHAUSTED|quota reached|quota exceeded|code 429|\b429\b|rate.?limit(ed)?|Resets in \d",
    re.IGNORECASE,
)
_RESET_RE = re.compile(r"Resets in\s+((?:\d+\s*[dhms]\s*)+)", re.IGNORECASE)


# --------------------------------------------------------------------------- helpers
def model_family(model: str) -> str:
    m = (model or "").lower()
    if "flash" in m:
        return "gemini-flash"
    if "gemini" in m or "argon" in m:
        return "gemini-argon"
    if "opus" in m:
        return "claude-opus"
    if "sonnet" in m or "claude" in m:
        return "claude-sonnet"
    if "gpt" in m:
        return "gpt-oss"
    return "gemini-argon"


def quota_pool(family: str) -> str:
    """Families that share one quota bucket (Gemini models share a single pool)."""
    if family.startswith("gemini"):
        return "gemini"
    if family.startswith("claude"):
        return "claude"
    return family


def model_effort(model: str, default: str = "medium") -> str:
    m = (model or "").lower()
    for suf in _EFFORTS:
        if m.endswith(f"-{suf}"):
            return suf
    return default


def model_for(family: str, effort: str) -> str:
    table = FAMILY_MODELS[family]
    eff = effort if effort in table else ("high" if effort in ("xhigh", "max") else "medium")
    return table.get(eff) or next(iter(table.values()))


def friendly_name(model: str) -> str:
    return FRIENDLY.get(model_family(model), model)


def is_quota_error(text: str) -> bool:
    return bool(text) and bool(_QUOTA_RE.search(text))


def parse_reset_seconds(text: str) -> Optional[int]:
    match = _RESET_RE.search(text or "")
    if not match:
        return None
    total = 0
    for num, unit in re.findall(r"(\d+)\s*([dhms])", match.group(1).lower()):
        total += int(num) * {"d": 86400, "h": 3600, "m": 60, "s": 1}[unit]
    return total or None


def fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, _ = divmod(rem, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m"


# --------------------------------------------------------------------------- state
def _load() -> dict:
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(STATE_PATH.parent), prefix=".mq_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, STATE_PATH)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _active_cooldowns(now: Optional[float] = None) -> dict[str, dict]:
    now = now or time.time()
    pools = _load().get("pools", {})
    return {p: v for p, v in pools.items() if float(v.get("until", 0)) > now}


def is_available(model: str, now: Optional[float] = None) -> bool:
    return quota_pool(model_family(model)) not in _active_cooldowns(now)


def record_quota_hit(model: str, error_text: str = "") -> dict:
    """Mark the model's quota pool exhausted until its reported reset time."""
    pool = quota_pool(model_family(model))
    secs = parse_reset_seconds(error_text) or DEFAULT_COOLDOWN_SECONDS
    now = time.time()
    with _LOCK:
        data = _load()
        pools = data.setdefault("pools", {})
        pools[pool] = {
            "until": now + secs,
            "reset_in_seconds": secs,
            "hit_model": model,
            "recorded_at": now,
            "error": (error_text or "")[:240],
        }
        data["updated_at"] = now
        _save(data)
    return pools[pool]


def clear(pool: Optional[str] = None) -> None:
    with _LOCK:
        data = _load()
        if pool:
            data.get("pools", {}).pop(pool, None)
        else:
            data["pools"] = {}
        _save(data)


def fallback_chain(model: str, effort: Optional[str] = None) -> list[tuple[str, str]]:
    """Full ordered (model, effort) chain for a requested model, ignoring quota state."""
    fam = model_family(model)
    eff = (effort or model_effort(model)).lower()
    chain: list[tuple[str, str]] = [(model, model_effort(model, eff))]
    for f in FALLBACK_ORDER.get(fam, FALLBACK_ORDER["gemini-argon"]):
        cand = model_for(f, eff)
        if cand not in (c[0] for c in chain):
            chain.append((cand, model_effort(cand, eff)))
    return chain


def pick_available(model: str, effort: Optional[str] = None, exclude: tuple[str, ...] = ()) -> tuple[str, str]:
    """Best usable (model, effort): the requested model if its pool has quota, else the next fallback."""
    cooled = _active_cooldowns()
    chain = [c for c in fallback_chain(model, effort) if c[0] not in exclude]
    for cand, eff in chain:
        if quota_pool(model_family(cand)) not in cooled:
            return cand, eff
    # Everything is cooling down: use the pool that resets soonest.
    if chain:
        return min(chain, key=lambda c: float(cooled.get(quota_pool(model_family(c[0])), {}).get("until", 0)))
    return model, model_effort(model, effort or "medium")


def next_after_quota(failed_model: str, error_text: str, effort: Optional[str] = None,
                     tried: tuple[str, ...] = ()) -> Optional[tuple[str, str]]:
    """Record a quota hit and return the next model to try (None if no untried pool remains)."""
    record_quota_hit(failed_model, error_text)
    cooled = _active_cooldowns()
    for cand, eff in fallback_chain(failed_model, effort):
        if cand == failed_model or cand in tried:
            continue
        if quota_pool(model_family(cand)) not in cooled:
            return cand, eff
    return None


def failover_note(requested: str, used: str) -> str:
    """One-line human notice for chat UIs (Discord subtext / MiTH-CLI)."""
    if model_family(requested) == model_family(used) and requested == used:
        return ""
    pool = quota_pool(model_family(requested))
    info = _active_cooldowns().get(pool, {})
    reset = f" (resets in {fmt_duration(float(info['until']) - time.time())})" if info else ""
    return f"↪️ {friendly_name(requested)} quota maxed{reset} — answered with {friendly_name(used)}."


def status_lines() -> list[str]:
    now = time.time()
    cooled = _active_cooldowns(now)
    lines = []
    for pool in ("gemini", "claude", "gpt-oss"):
        if pool in cooled:
            lines.append(f"{pool:8s} EXHAUSTED  resets in {fmt_duration(float(cooled[pool]['until']) - now)}")
        else:
            lines.append(f"{pool:8s} available")
    return lines


# --------------------------------------------------------------------------- self test
def _selftest() -> int:
    global STATE_PATH
    real = STATE_PATH
    STATE_PATH = Path(tempfile.mkdtemp()) / "state.json"
    err = ("error: Individual quota reached. Please upgrade your subscription to increase your limits. "
           "Resets in 68h27m38s.\nAGY_ERROR: {\"status\":\"RESOURCE_EXHAUSTED\",\"error_code\":429}")
    try:
        assert is_quota_error(err)
        assert not is_quota_error("agy exited with code 1: unknown flag")
        assert parse_reset_seconds(err) == 68 * 3600 + 27 * 60 + 38
        assert pick_available("gemini-4-argon-medium") == ("gemini-4-argon-medium", "medium")
        nxt = next_after_quota("gemini-4-argon-medium", err)
        assert nxt == ("claude-sonnet-5-5-medium", "medium"), nxt
        # Flash shares the Gemini pool -> also skipped
        assert pick_available("gemini-3.8-flash-high")[0] == "claude-sonnet-5-5-high"
        assert pick_available("claude-opus-5-5-high")[0] == "claude-opus-5-5-high"
        nxt2 = next_after_quota("claude-opus-5-5-high", "Resets in 2h", tried=("gemini-4-argon-high",))
        assert nxt2 == ("gpt-oss-120b-medium", "medium"), nxt2
        assert "quota maxed" in failover_note("gemini-4-argon-medium", "gpt-oss-120b-medium")
        clear()
        assert pick_available("gemini-4-argon-high")[0] == "gemini-4-argon-high"
        print("model_failover selftest: PASS")
        return 0
    finally:
        STATE_PATH = real


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "status":
        print("\n".join(status_lines()))
    elif cmd == "chain":
        tgt = sys.argv[2] if len(sys.argv) > 2 else "gemini-4-argon-medium"
        print("chain:", fallback_chain(tgt))
        print("pick :", pick_available(tgt))
    elif cmd == "clear":
        clear(sys.argv[2] if len(sys.argv) > 2 else None)
        print("cleared")
    elif cmd == "selftest":
        sys.exit(_selftest())
    else:
        print(__doc__)
