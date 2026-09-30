"""OSINT enrichment API-key config for the dashboard Config Page.

tools/enrichment.py reads these env vars directly (module-level
os.environ.get at import time) and every one of them is optional — Atlas
degrades gracefully, with the matching enrichment.* tool reporting
unavailable, when a key is unset. This module is the write path only; it
uses the same envfile.save_secret_value() helper as dashboard/config_llm.py
so the keyring-vs-.env decision and fallback behavior can't drift between
the two config pages. Writes are serialized by core/envfile.py's own lock
(see its lock() docstring), not a lock owned by this module, so a concurrent
save on the LLM or mail config page can't race this one.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from core import envfile

_REPO_ROOT = Path(__file__).resolve().parents[1]

# One entry per enrichment.* integration that needs credentials — see
# tools/enrichment.py's own env lookups at module load for the source of
# truth this mirrors. MISP is the only one needing a URL alongside its key.
FIELDS: tuple[dict, ...] = (
    {"id": "virustotal", "label": "VirusTotal", "key_var": "VIRUSTOTAL_API_KEY",
     "description": "File hash, IP, and domain reputation lookups — malware "
                     "verdicts and related samples for an indicator."},
    {"id": "abuseipdb", "label": "AbuseIPDB", "key_var": "ABUSEIPDB_API_KEY",
     "description": "Has this IP been reported for malicious activity? "
                     "Abuse-report history and confidence score."},
    {"id": "otx", "label": "AlienVault OTX", "key_var": "OTX_API_KEY",
     "description": "Threat-intel pulses (community-reported context) "
                     "related to an IP, domain, or file hash."},
    {"id": "urlscan", "label": "urlscan.io", "key_var": "URLSCAN_API_KEY",
     "description": "Has this URL or page been seen/scanned before? "
                     "Search prior scan history by URL or query."},
    {"id": "misp", "label": "MISP", "key_var": "MISP_API_KEY",
     "url_var": "MISP_URL",
     "description": "Search your own MISP threat-intel instance for "
                     "attributes matching an indicator — needs your MISP "
                     "server's URL too, set below."},
)
_BY_ID = {f["id"]: f for f in FIELDS}


class ConfigError(Exception):
    """Raised for validation/precondition failures — safe to show the admin."""


def _env_path() -> Path:
    path = envfile.resolve(_REPO_ROOT)
    if not path.is_file():
        raise ConfigError(
            f"no .env at {path} — create it first (cp .env.example .env)")
    return path


def status() -> dict:
    """Config-page display — never returns key values, only whether set."""
    fields = []
    for f in FIELDS:
        entry = {"id": f["id"], "label": f["label"],
                 "description": f.get("description", ""),
                 "key_set": bool(os.environ.get(f["key_var"]))}
        if "url_var" in f:
            entry["url"] = os.environ.get(f["url_var"], "")
        fields.append(entry)
    return {"fields": fields}


def save_config(data: dict[str, Any]) -> dict:
    """data: {<field id>: {api_key: "" (""=unchanged), url: "" (misp only),
    store_key_in: "keyring"|"env"}, ...}. Only fields present are touched;
    an empty api_key leaves the stored key unchanged (matches config_llm.py's
    provider-key convention)."""
    env_path = _env_path()
    results: dict[str, dict] = {}
    with envfile.lock():
        for field_id, payload in data.items():
            f = _BY_ID.get(field_id)
            if f is None or not isinstance(payload, dict):
                continue
            if "url_var" in f and "url" in payload:
                url = str(payload.get("url") or "")
                envfile.set_values(env_path, {f["url_var"]: url})
                os.environ[f["url_var"]] = url
            api_key = str(payload.get("api_key") or "")
            if not api_key:
                results[field_id] = {"stored": "skip"}
                continue
            results[field_id] = envfile.save_secret_value(
                _REPO_ROOT, env_path, f["key_var"], api_key,
                str(payload.get("store_key_in") or "env"))
    # "saved" (per-field write outcome: stored where, keyring_failed?) is
    # deliberately a different key than status()'s "fields" (field
    # display list) — merging them under one key would let one silently
    # clobber the other.
    return {"success": True, "saved": results, **status()}
