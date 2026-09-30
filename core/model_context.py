"""Probe provider model metadata for context window size — no local catalogue.

Before each run Atlas can ``GET {base}/models``, find the configured model id,
and read whatever context field the provider exposes (OpenRouter
``context_length``, vLLM ``max_model_len``, nested ``top_provider``, …).

Operator overrides always win:

* ``ATLAS_MODEL_CONTEXT_TOKENS`` — hard window override (skip probe for budget)
* ``ATLAS_MODEL_CONTEXT_PROBE=0`` — disable network probe
* ``ATLAS_CONTEXT_CHARS_LOCK=1`` — do not auto-move ``ATLAS_AGENT_CONTEXT_CHARS``

On probe failure, a short-lived disk cache (``~/.atlas/model_context_cache.json``)
may supply the last known window for the same base URL + model id.
"""
from __future__ import annotations

import json
import os
import time

from core.envfile import env_float
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

SCHEMA_VERSION = "1.0"

# Last-resort window when the live probe fails/is disabled AND there is no
# cached window for this base URL + model AND the operator has not set
# ATLAS_MODEL_CONTEXT_TOKENS. Conservative relative to GLM-5.2's 1M-token
# product default (core.llm_check.DEFAULT_WINDOW), which would silently
# under-trim requests for a smaller model — but NOT small in absolute terms.
#
# It has a hard floor: Atlas's own assembled system prompt (hub/ENTRY.md +
# hub/playbook/*.md + case seed) measures ~25k tokens, so a window whose
# send budget lands under that makes the very first turn unfittable and
# every probe-failure run dies before it starts. 32k was tried and did
# exactly that. 128k leaves ~96k of send budget — roughly 4x the playbook —
# and is at or below the real context of every mainstream model Atlas
# targets. Operators on genuinely smaller local models set
# ATLAS_MODEL_CONTEXT_TOKENS. Guarded by
# test_conservative_fallback_window_fits_the_real_system_prompt.
_CONSERVATIVE_FALLBACK_WINDOW = 128_000

# Process-level result of the latest successful apply (or cache hit).
_probed_window: int | None = None
_probed_meta: dict[str, Any] = {}

_LogFn = Callable[[str], None]

# Common OpenAI-compatible / gateway field names — probed from live JSON only.
_CONTEXT_KEYS = (
    "context_length",
    "context_window",
    "max_model_len",
    "max_sequence_length",
    "max_position_embeddings",
    "max_tokens",
    "max_input_tokens",
    "input_token_limit",
)


def _truthy(name: str, default: str = "0") -> bool:
    return (os.environ.get(name) or default).strip().lower() in (
        "1", "true", "yes", "on",
    )


def probe_enabled() -> bool:
    return _truthy("ATLAS_MODEL_CONTEXT_PROBE", "1")


def cache_path() -> Path:
    override = (os.environ.get("ATLAS_MODEL_CONTEXT_CACHE") or "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".atlas" / "model_context_cache.json"


def cache_ttl_seconds() -> int:
    raw = (os.environ.get("ATLAS_MODEL_CONTEXT_CACHE_TTL") or "").strip()
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    return 7 * 24 * 3600  # one week fallback if a run's probe fails


def get_probed_window() -> int | None:
    """Window tokens from the latest probe/apply in this process, if any."""
    return _probed_window


def get_probed_meta() -> dict[str, Any]:
    return dict(_probed_meta)


def clear_probed_window() -> None:
    """Test helper."""
    global _probed_window, _probed_meta
    _probed_window = None
    _probed_meta = {}


def _cache_key(base_url: str, model: str) -> str:
    return f"{(base_url or '').rstrip('/').lower()}|{(model or '').strip()}"


def _load_cache() -> dict[str, Any]:
    path = cache_path()
    try:
        if not path.is_file():
            return {"schema_version": SCHEMA_VERSION, "models": {}}
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"schema_version": SCHEMA_VERSION, "models": {}}
        models = data.get("models")
        if not isinstance(models, dict):
            data["models"] = {}
        return data
    except Exception:
        return {"schema_version": SCHEMA_VERSION, "models": {}}


def _save_cache(data: dict[str, Any]) -> None:
    path = cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp, path)
    except OSError:
        pass


def _coerce_tokens(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        n = int(float(value))
    except (TypeError, ValueError):
        return None
    # Reject nonsense (chat max_tokens often 4k–64k completion caps — still
    # usable as a lower bound; floor keeps garbage out).
    if n < 4096:
        return None
    if n > 10_000_000:
        return None
    return n


def extract_context_tokens(entry: dict[str, Any] | None) -> tuple[int | None, str]:
    """Pull a context-window size from a provider model object.

    Returns ``(tokens, source_field)``. No catalogue — only keys present on
    the live object (and a few well-known nests).
    """
    if not isinstance(entry, dict):
        return None, ""

    def from_mapping(obj: dict[str, Any], prefix: str = "") -> tuple[int | None, str]:
        for key in _CONTEXT_KEYS:
            if key not in obj:
                continue
            n = _coerce_tokens(obj.get(key))
            if n is not None:
                return n, f"{prefix}{key}" if prefix else key
        return None, ""

    n, src = from_mapping(entry)
    if n is not None:
        return n, src

    for nest_name in ("top_provider", "architecture", "limits", "meta", "settings"):
        nest = entry.get(nest_name)
        if isinstance(nest, dict):
            n, src = from_mapping(nest, prefix=f"{nest_name}.")
            if n is not None:
                return n, src

    # Some gateways bury limits under pricing or provider arrays — ignore
    # pricing amounts; only scan dict values one level deep for context keys.
    for key, val in entry.items():
        if not isinstance(val, dict):
            continue
        if key in ("pricing", "permissions"):
            continue
        n, src = from_mapping(val, prefix=f"{key}.")
        if n is not None:
            return n, src

    return None, ""


def match_model_entry(
    entries: list[dict[str, Any]],
    model_id: str,
) -> dict[str, Any] | None:
    """Find the catalogue row for ``model_id`` (exact, then light aliases)."""
    want = (model_id or "").strip()
    if not want:
        return None
    by_id = {
        str(e.get("id") or "").strip(): e
        for e in entries
        if isinstance(e, dict) and e.get("id")
    }
    if want in by_id:
        return by_id[want]
    # OpenRouter style: configured id may omit / include :free|:nitro|:batch
    if ":" in want:
        base = want.split(":", 1)[0]
        if base in by_id:
            return by_id[base]
    # Configured bare id, catalogue has :free variant with larger window —
    # prefer exact-prefix match with longest id ending in configured base.
    candidates = [
        e for mid, e in by_id.items()
        if mid == want or mid.startswith(want + ":") or mid.startswith(want + "/")
    ]
    if len(candidates) == 1:
        return candidates[0]
    if candidates:
        # Prefer an entry that actually exposes context metadata.
        scored: list[tuple[int, dict[str, Any]]] = []
        for e in candidates:
            n, _ = extract_context_tokens(e)
            scored.append((n or 0, e))
        scored.sort(key=lambda t: t[0], reverse=True)
        if scored[0][0] > 0:
            return scored[0][1]
        return candidates[0]

    # Case-insensitive fallback
    want_l = want.casefold()
    for mid, e in by_id.items():
        if mid.casefold() == want_l:
            return e
    return None


@dataclass
class ProbeResult:
    success: bool
    window_tokens: int | None = None
    model: str = ""
    provider: str = ""
    base_url: str = ""
    source: str = ""  # live | cache | env_override | disabled | error
    source_field: str = ""
    error: str = ""
    adapted_chars: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "window_tokens": self.window_tokens,
            "model": self.model,
            "provider": self.provider,
            "base_url": self.base_url,
            "source": self.source,
            "source_field": self.source_field,
            "error": self.error,
            "adapted_chars": self.adapted_chars,
        }


def _read_cache_entry(base_url: str, model: str) -> tuple[int | None, str]:
    data = _load_cache()
    entry = (data.get("models") or {}).get(_cache_key(base_url, model))
    if not isinstance(entry, dict):
        return None, ""
    tokens = _coerce_tokens(entry.get("window_tokens"))
    if tokens is None:
        return None, ""
    probed_at = float(entry.get("probed_at") or 0)
    ttl = cache_ttl_seconds()
    if ttl > 0 and probed_at > 0 and (time.time() - probed_at) > ttl:
        return None, "cache_expired"
    return tokens, str(entry.get("source_field") or "cache")


def _write_cache_entry(
    base_url: str,
    model: str,
    window_tokens: int,
    *,
    source_field: str,
    provider: str,
) -> None:
    data = _load_cache()
    models = data.setdefault("models", {})
    models[_cache_key(base_url, model)] = {
        "window_tokens": int(window_tokens),
        "source_field": source_field,
        "provider": provider,
        "model": model,
        "base_url": base_url.rstrip("/"),
        "probed_at": time.time(),
    }
    data["schema_version"] = SCHEMA_VERSION
    _save_cache(data)


def fetch_models_payload(
    *,
    base_url: str,
    headers: dict[str, str],
    timeout: float = 20.0,
) -> list[dict[str, Any]]:
    """GET /models and return the ``data`` list (empty if malformed)."""
    import httpx
    from core import llmhub

    url = llmhub.build_models_url(base_url)
    resp = httpx.get(url, headers=headers, timeout=timeout)
    if resp.status_code >= 400:
        raise RuntimeError(f"HTTP {resp.status_code} from {url}: {resp.text[:240]}")
    body = resp.json()
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, list):
        # Some servers return a bare list
        if isinstance(body, list):
            data = body
        else:
            raise RuntimeError(f"unexpected /models body from {url}")
    return [e for e in data if isinstance(e, dict)]


def derived_context_chars(window_tokens: int) -> int:
    """Chars to keep in the agent conversation for this window.

    Delegates to ``core.llm_check`` (75% of the window, chars/4).
    """
    from core.llm_check import limits_for_window
    return limits_for_window(window_tokens).context_chars


def adapt_agent_context_chars(
    window_tokens: int,
    *,
    model: str = "",
    provider: str = "",
) -> int | None:
    """Move ``ATLAS_AGENT_CONTEXT_CHARS`` to the derived window budget.

    Grows for ~1M models and shrinks for small windows. Returns None when
    auto-adapt is locked off; session tool limits are still installed.
    """
    from core.llm_check import apply_session_window
    adapt = _truthy("ATLAS_CONTEXT_AUTO_CHARS", "1") and not _truthy(
        "ATLAS_CONTEXT_CHARS_LOCK", "0")
    lim = apply_session_window(
        window_tokens, model=model, provider=provider, adapt_chars=adapt)
    if not adapt:
        return None
    return lim.context_chars


def apply_window(
    window_tokens: int,
    *,
    model: str = "",
    provider: str = "",
    base_url: str = "",
    source: str = "live",
    source_field: str = "",
    adapt_chars: bool = True,
) -> ProbeResult:
    """Install a window into process state and scale send-side budgets."""
    global _probed_window, _probed_meta
    tokens = _coerce_tokens(window_tokens)
    if tokens is None:
        return ProbeResult(
            success=False,
            model=model,
            provider=provider,
            base_url=base_url,
            source="error",
            error=f"invalid window_tokens={window_tokens!r}",
        )
    _probed_window = tokens
    if adapt_chars:
        adapted = adapt_agent_context_chars(
            tokens, model=model, provider=provider)
    else:
        from core.llm_check import apply_session_window
        apply_session_window(
            tokens, model=model, provider=provider, adapt_chars=False)
        adapted = None
    _probed_meta = {
        "window_tokens": tokens,
        "model": model,
        "provider": provider,
        "base_url": base_url,
        "source": source,
        "source_field": source_field,
        "adapted_chars": adapted,
    }
    return ProbeResult(
        success=True,
        window_tokens=tokens,
        model=model,
        provider=provider,
        base_url=base_url,
        source=source,
        source_field=source_field,
        adapted_chars=adapted,
    )


def probe_model_context(
    *,
    base_url: str,
    headers: dict[str, str],
    model: str,
    provider: str = "",
    timeout: float | None = None,
    persist_cache: bool = True,
    use_cache_on_failure: bool = True,
) -> ProbeResult:
    """Network probe for one model. Fail-open with optional cache fallback."""
    model = (model or "").strip()
    base_url = (base_url or "").strip()
    if not model or not base_url:
        return ProbeResult(
            success=False,
            model=model,
            provider=provider,
            base_url=base_url,
            source="error",
            error="missing model or base_url",
        )
    if not probe_enabled():
        return ProbeResult(
            success=False,
            model=model,
            provider=provider,
            base_url=base_url,
            source="disabled",
            error="ATLAS_MODEL_CONTEXT_PROBE disabled",
        )

    # Explicit operator override — still report it, skip network.
    explicit = (os.environ.get("ATLAS_MODEL_CONTEXT_TOKENS") or "").strip()
    if explicit:
        try:
            n = max(4096, int(explicit))
            return ProbeResult(
                success=True,
                window_tokens=n,
                model=model,
                provider=provider,
                base_url=base_url,
                source="env_override",
                source_field="ATLAS_MODEL_CONTEXT_TOKENS",
            )
        except ValueError:
            pass

    if timeout is None:
        timeout = env_float("ATLAS_MODEL_CONTEXT_PROBE_TIMEOUT", 20.0)

    try:
        entries = fetch_models_payload(
            base_url=base_url, headers=headers, timeout=timeout)
        entry = match_model_entry(entries, model)
        if entry is None:
            return ProbeResult(
                success=False,
                model=model,
                provider=provider,
                base_url=base_url,
                source="unknown_model",
                error=(
                    f"model {model!r} is not available from provider "
                    f"{provider or 'this endpoint'!r} "
                    f"({len(entries)} models listed)"
                ),
            )
        tokens, field = extract_context_tokens(entry)
        if tokens is None:
            raise RuntimeError(
                f"model {model!r} found but no context_length-like field"
            )
        if persist_cache:
            _write_cache_entry(
                base_url, model, tokens,
                source_field=field, provider=provider,
            )
        return ProbeResult(
            success=True,
            window_tokens=tokens,
            model=model,
            provider=provider,
            base_url=base_url,
            source="live",
            source_field=field,
        )
    except Exception as exc:
        err = f"{type(exc).__name__}: {exc}"
        if use_cache_on_failure:
            cached, why = _read_cache_entry(base_url, model)
            if cached is not None:
                return ProbeResult(
                    success=True,
                    window_tokens=cached,
                    model=model,
                    provider=provider,
                    base_url=base_url,
                    source="cache",
                    source_field=why or "cache",
                    error=err,
                )
        return ProbeResult(
            success=False,
            model=model,
            provider=provider,
            base_url=base_url,
            source="error",
            error=err,
        )


def probe_and_apply(
    provider: Any,
    model: str,
    *,
    log: _LogFn | None = None,
    warn: _LogFn | None = None,
) -> ProbeResult:
    """Probe the provider for ``model`` and install the window into process state."""
    base_url = getattr(provider, "base_url", "") or ""
    headers = {}
    try:
        headers = dict(provider.headers())
    except Exception:
        headers = {"Content-Type": "application/json"}
    prov_name = getattr(provider, "name", "") or ""

    result = probe_model_context(
        base_url=base_url,
        headers=headers,
        model=model or getattr(provider, "model", "") or "",
        provider=prov_name,
    )
    if result.success and result.window_tokens:
        applied = apply_window(
            result.window_tokens,
            model=result.model,
            provider=result.provider,
            base_url=result.base_url,
            source=result.source,
            source_field=result.source_field,
            adapt_chars=result.source != "env_override",
        )
        # Preserve env_override source label; merge adapted chars.
        result = ProbeResult(
            success=True,
            window_tokens=applied.window_tokens,
            model=result.model,
            provider=result.provider,
            base_url=result.base_url,
            source=result.source,
            source_field=result.source_field,
            error=result.error,
            adapted_chars=applied.adapted_chars,
        )
        if log:
            bits = [
                f"model context: {result.window_tokens} tokens",
                f"via {result.source}",
            ]
            if result.source_field:
                bits.append(f"field={result.source_field}")
            if result.adapted_chars:
                bits.append(f"agent_context_chars={result.adapted_chars}")
            try:
                from core.llm_check import session_limits
                lim = session_limits()
                if lim is not None:
                    bits.append(f"policy={lim.detail_policy}")
                    if lim.disk_first:
                        bits.append("disk-first")
            except Exception:
                pass
            log(" · ".join(bits))
        if result.error and warn:
            warn(f"model context probe fell back ({result.error[:160]})")
        return result

    if result.source == "unknown_model":
        if warn:
            warn(result.error or "model is not in the provider catalogue")
        return result

    # Network / disabled probe: install a conservative window so send
    # budgets exist without guessing the operator is on GLM-5.2's 1M-token
    # window. DEFAULT_WINDOW is a *product default for a confirmed GLM-5.2*,
    # not a safe blind guess — a smaller model behind a dead probe would
    # otherwise get a budget many times its real context, and llm_check's
    # send-side trimming would under-trim, leaving the provider to silently
    # head-truncate the request. Operators can
    # still set ATLAS_MODEL_CONTEXT_TOKENS for a smaller (or larger)
    # confirmed window, or wait for a successful live probe.
    explicit = (os.environ.get("ATLAS_MODEL_CONTEXT_TOKENS") or "").strip()
    fallback = _CONSERVATIVE_FALLBACK_WINDOW
    if explicit:
        try:
            fallback = max(4096, int(explicit))
        except ValueError:
            pass
    applied = apply_window(
        fallback,
        model=result.model,
        provider=result.provider,
        base_url=result.base_url,
        source="conservative_fallback",
        adapt_chars=True,
    )
    if warn:
        warn(
            "model context probe failed — using a conservative "
            f"{applied.window_tokens} token window (unconfirmed; "
            f"{(result.error or 'unknown')[:120]}). "
            "Set ATLAS_MODEL_CONTEXT_TOKENS to the model's real context "
            "size for an accurate budget."
        )
    return ProbeResult(
        # The live probe itself failed — this is a guessed fallback, not a
        # confirmed window. success=False says so honestly; window_tokens
        # and the applied budgets are still installed either way so a
        # session always has *some* working send budget.
        success=False,
        window_tokens=applied.window_tokens,
        model=result.model,
        provider=result.provider,
        base_url=result.base_url,
        source="conservative_fallback",
        source_field=result.source_field,
        error=result.error,
        adapted_chars=applied.adapted_chars,
    )
