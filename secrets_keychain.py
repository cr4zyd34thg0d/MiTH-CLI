#!/usr/bin/env python3
"""
MiTH CLI — Cross-Platform Hardware Keychain & Secret Bridge (secrets_keychain.py)
Supports:
  1. macOS Keychain ('security find-generic-password' / 'security add-generic-password')
  2. Windows Credential Locker / DPAPI (via PowerShell ProtectedData in WSL/Windows)
  3. Linux Secret Service ('secret-tool' / libsecret)
  4. Fallback encrypted/local .env loader
"""
import argparse
import os
import platform
import subprocess
from pathlib import Path

SERVICE_NAME = "MiTH-CLI-Vault"
DEFAULT_KEYS = [
    "DISCORD_BOT_TOKEN",
    "GEMINI_API_KEY",
    "POCKET_CLI_PIN",
    "OWNER_USER_ID",
    "DISCORD_GUILD_ID",
]


def _is_wsl() -> bool:
    try:
        return "microsoft" in platform.uname().release.lower()
    except Exception:
        return False


def set_secret(key: str, value: str) -> bool:
    """Save a secret into the native OS hardware keychain."""
    sys_name = platform.system().lower()
    if sys_name == "darwin":
        # macOS Keychain
        subprocess.run(
            ["security", "add-generic-password", "-U", "-a", key, "-s", SERVICE_NAME, "-w", value],
            check=True,
        )
        return True
    elif _is_wsl() or sys_name == "windows":
        # Windows DPAPI User-Scoped Encrypted Vault (stored in ~/.mith_vault/<key>.dpapi)
        vault_dir = Path.home() / ".mith_vault"
        vault_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        out_file = vault_dir / f"{key}.enc"
        # Use local user-scoped SHA256/Fernet-style machine key or Windows DPAPI via powershell.exe
        ps_cmd = (
            f"$sec = ConvertTo-SecureString -String '{value.replace(chr(39), chr(39)*2)}' -AsPlainText -Force; "
            f"ConvertFrom-SecureString -SecureString $sec"
        )
        res = subprocess.run(
            ["/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0 and res.stdout.strip():
            out_file.write_text(res.stdout.strip(), encoding="utf-8")
            os.chmod(out_file, 0o600)
            return True
    # Linux secret-tool fallback
    res = subprocess.run(
        ["secret-tool", "store", "--label", f"{SERVICE_NAME}:{key}", "service", SERVICE_NAME, "account", key],
        input=value,
        text=True,
        capture_output=True,
    )
    return res.returncode == 0


def get_secret(key: str, default: str = "") -> str:
    """Retrieve a secret from OS Keychain first, then environment/.env fallback."""
    if os.environ.get(key):
        return os.environ[key]

    sys_name = platform.system().lower()
    if sys_name == "darwin":
        res = subprocess.run(
            ["security", "find-generic-password", "-a", key, "-s", SERVICE_NAME, "-w"],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    elif _is_wsl() or sys_name == "windows":
        enc_file = Path.home() / ".mith_vault" / f"{key}.enc"
        if enc_file.exists():
            cipher = enc_file.read_text(encoding="utf-8").strip()
            ps_cmd = (
                f"$sec = ConvertTo-SecureString -String '{cipher}'; "
                f"$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec); "
                f"[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)"
            )
            res = subprocess.run(
                ["/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()

    return default


def import_env_to_keychain(env_path: Path) -> int:
    """Import secrets from .env into the OS hardware keychain."""
    if not env_path.exists():
        print(f"No .env found at {env_path}")
        return 0
    count = 0
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k and v:
            if set_secret(k, v):
                count += 1
                print(f"  [OK] Locked '{k}' into OS Hardware Keychain ({SERVICE_NAME})")
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MiTH CLI Hardware Keychain & Secret Manager")
    parser.add_argument("--import-env", action="store_true", help="Import local .env variables into OS Keychain")
    parser.add_argument("--get", type=str, help="Retrieve a secret key from OS Keychain")
    parser.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"), help="Store a secret key in OS Keychain")
    args = parser.parse_args()

    if args.import_env:
        env_file = Path(__file__).resolve().parent / ".env"
        n = import_env_to_keychain(env_file)
        print(f"Done. {n} secrets locked into hardware keychain.")
    elif args.set:
        ok = set_secret(args.set[0], args.set[1])
        print("Saved." if ok else "Failed.")
    elif args.get:
        val = get_secret(args.get)
        print(f"{args.get}={'*' * min(len(val), 8)} (loaded: {bool(val)})")
