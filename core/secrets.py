"""
Loads secrets (API keys) from the GNOME Keyring (via `secret-tool`) into
os.environ, for names not already set by the shell environment or .env.

Secrets are stored under service="atlas-sift", key=<ENV_VAR_NAME>. Use
`bin/atlas-secret set REASON_API_KEY` to store one. Explicit environment
variables (including from .env) always take priority over the keyring, so
this is additive — it never overrides a value that's already set.

Default behaviour: if a primary LLM key is already set (``.env`` / shell),
**skip the keyring entirely**. Looking up *unset* optional keys
(VirusTotal, MISP, …) still talks to the Secret Service and will pop an
“Unlock Keyring” GUI dialog when the collection is locked — which is the
common WSL/desktop case when keys already live in `.env`.

Opt in to keyring probes with ``ATLAS_USE_KEYRING=1``. Force off with
``ATLAS_NO_KEYRING=1``.

No-ops silently if `secret-tool` isn't installed or lookups fail
(e.g. a headless session with no D-Bus session bus).
"""
from __future__ import annotations

import os
import shutil
import subprocess

SECRET_SERVICE = "atlas-sift"

# Env vars this loader will attempt to fill from the keyring (when enabled).
MANAGED_KEYS = (
    "REASON_API_KEY",
    "DAIR_API_KEY",
    "ANTHROPIC_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    "OTX_API_KEY",
    "URLSCAN_API_KEY",
    "MISP_URL",
    "MISP_API_KEY",
    "LLMHUB_API_KEY",
    "TSYSTEMS_API_KEY",
)

# If any of these are already set, keyring is skipped unless ATLAS_USE_KEYRING=1.
_PRIMARY_LLM_KEYS = (
    "LLMHUB_API_KEY",
    "TSYSTEMS_API_KEY",
    "ANTHROPIC_API_KEY",
    "REASON_API_KEY",
)


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def keyring_lookups_enabled() -> bool:
    """Whether ``secret-tool`` probes are allowed this process."""
    if _truthy("ATLAS_NO_KEYRING"):
        return False
    if _truthy("ATLAS_USE_KEYRING"):
        return True
    # .env / shell already has a usable LLM credential — do not poke optional
    # keys in the vault (that unlocks GNOME keyring GUI prompts).
    if any(os.environ.get(k) for k in _PRIMARY_LLM_KEYS):
        return False
    return True


def managed_keys() -> tuple[str, ...]:
    """MANAGED_KEYS plus the API-key var of every provider in ATLAS_PROVIDERS.

    Provider names are configuration, so this cannot be a static tuple: a
    gateway token has to be storable in the keyring like every other Atlas
    credential instead of sitting in `.env`, which is a file in the working
    tree.
    """
    from core import providers
    extra = tuple(name for name in providers.api_key_env_names()
                  if name not in MANAGED_KEYS)
    return MANAGED_KEYS + extra


def _lookup(key: str) -> str | None:
    try:
        result = subprocess.run(
            ["secret-tool", "lookup", "service", SECRET_SERVICE, "key", key],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    value = result.stdout
    return value if value else None


def load_into_environ(keys: tuple[str, ...] | None = None) -> list[str]:
    """Fill os.environ[key] from the keyring for any key not already set.

    Defaults to managed_keys(), resolved per call because the declared
    providers come from the environment.

    Returns the list of keys actually filled from the keyring (for logging).
    """
    if not keyring_lookups_enabled():
        return []
    if shutil.which("secret-tool") is None:
        return []
    if keys is None:
        keys = managed_keys()
    filled = []
    for key in keys:
        if os.environ.get(key):
            continue  # explicit env / .env value wins
        value = _lookup(key)
        if value:
            os.environ[key] = value
            filled.append(key)
    return filled
