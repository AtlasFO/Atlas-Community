"""The price list on Settings, Token spend.

One row per provider|model the LLM settings name or the usage ledger has
recorded. A row appears on its own when its model first appears in the LLM
settings (or appears there again after it was removed) and the first time the
ledger records it; it goes away only when the admin deletes it, or, with
``llm_price_autoremove`` set, when its model leaves the LLM settings. What was
offered is remembered (``llm_price_models``: ``{key: {listed, configured}}``),
so a deleted row stays deleted.

The same pass relabels ledger rows that carry a host where one configured
provider owns that host; their saved price moves with them.
"""
from __future__ import annotations

import json
import math
import threading
from typing import Any, Optional

from core import usage_import, usage_ledger
from dashboard import auth

MODELS = "llm_price_models"
PRICES = "llm_prices"
CURRENCY = "llm_price_currency"
AUTOREMOVE = "llm_price_autoremove"

_lock = threading.Lock()


class PriceError(ValueError):
    pass


def _load(key: str) -> dict:
    try:
        value = json.loads(auth.get_setting(key, "") or "{}")
    except ValueError:
        value = {}
    return value if isinstance(value, dict) else {}


def _store(key: str, value: dict) -> None:
    auth.set_setting(key, json.dumps(value, sort_keys=True))


def autoremove() -> bool:
    return auth.get_setting(AUTOREMOVE, "0") == "1"


def configured_keys() -> Optional[set[str]]:
    """provider|model of every model the LLM settings name, role model
    overrides included; None when the settings cannot be read, so a passing
    failure never reads as "every model was removed"."""
    from dashboard import config_llm
    try:
        data = config_llm.list_providers()
    except Exception:  # noqa: BLE001 - no .env, unreadable file
        return None
    keys = {usage_ledger.price_key(p["name"], p["model"])
            for p in data.get("providers") or [] if p.get("model")}
    keys |= {usage_ledger.price_key(o["provider"], o["model"])
             for o in data.get("model_overrides") or []
             if o.get("provider") and o.get("model")}
    return keys


def _zero(price: dict) -> bool:
    return not any(float(price.get(f) or 0) for f in ("input", "cached", "output"))


def _relabel(models: dict, prices: dict) -> bool:
    known = usage_import.configured()
    names = {n for n, _u, _m in known}
    changed = False
    for provider, model in usage_ledger.models_seen():
        if provider in names:
            continue
        name = usage_import.provider_for(provider, model, known)
        if not name or not usage_ledger.relabel_provider(old=provider, new=name, model=model):
            continue
        old = usage_ledger.price_key(provider, model)
        new = usage_ledger.price_key(name, model)
        old_price = prices.pop(old, None)
        if old_price is not None and (new not in prices
                                      or (_zero(prices[new]) and not _zero(old_price))):
            prices[new] = old_price
        entry = models.pop(old, None)
        if entry is not None or new not in models:
            models.setdefault(new, {"listed": True, "configured": False})["listed"] = True
        changed = True
    return changed


def sync() -> dict:
    """Bring the list up to date and return what the page shows."""
    with _lock:
        models, prices = _load(MODELS), _load(PRICES)
        before = json.dumps([models, prices], sort_keys=True)
        _relabel(models, prices)
        configured = configured_keys()
        if configured is not None:
            for key in configured:
                entry = models.get(key)
                if entry is None or not entry.get("configured"):
                    models[key] = {"listed": True, "configured": True}
            remove = autoremove()
            for key, entry in models.items():
                if entry.get("configured") and key not in configured:
                    entry["configured"] = False
                    if remove:
                        entry["listed"] = False
                        prices.pop(key, None)
        seen = {usage_ledger.price_key(p, m) for p, m in usage_ledger.models_seen()}
        for key in seen | set(prices):
            models.setdefault(key, {"listed": True, "configured": False})
        if json.dumps([models, prices], sort_keys=True) != before:
            _store(MODELS, models)
            _store(PRICES, prices)
        return _payload(models, prices, seen)


def _payload(models: dict, prices: dict, seen: set[str]) -> dict:
    rows = []
    for key in sorted(k for k, e in models.items() if e.get("listed")):
        provider, _sep, model = key.partition("|")
        rows.append({"key": key, "provider": provider, "model": model,
                     "configured": bool(models[key].get("configured")),
                     "used": key in seen})
    listed = {r["key"] for r in rows}
    return {"currency": auth.get_setting(CURRENCY, "EUR") or "EUR",
            "autoremove": autoremove(),
            "prices": {k: v for k, v in prices.items() if k in listed},
            "models": rows}


def delete(key: str) -> None:
    """Take a row off the list; it comes back only when its model is added
    to the LLM settings again."""
    with _lock:
        models, prices = _load(MODELS), _load(PRICES)
        entry = models.get(key)
        if entry is None or not entry.get("listed"):
            raise PriceError(f"{key!r} is not on the price list")
        entry["listed"] = False
        prices.pop(key, None)
        _store(MODELS, models)
        _store(PRICES, prices)


def clean_prices(raw: Any) -> dict:
    """The prices as the page sends them, checked: {key: {input, cached,
    output}}, input and output required, cached optional, all finite and
    not negative."""
    if not isinstance(raw, dict):
        raise PriceError("prices must be an object keyed by provider|model")
    clean = {}
    for key, val in raw.items():
        if not isinstance(key, str) or "|" not in key or not isinstance(val, dict):
            raise PriceError(f"bad price entry {key!r}")
        entry = {}
        for f in ("input", "cached", "output"):
            v = val.get(f)
            if v in (None, ""):
                if f == "cached":
                    entry[f] = None
                    continue
                raise PriceError(f"{key}: {f} price missing")
            try:
                n = float(v)
            except (TypeError, ValueError):
                raise PriceError(f"{key}: {f} is not a number") from None
            if not math.isfinite(n) or n < 0:
                raise PriceError(f"{key}: {f} must be a finite number of at least 0")
            entry[f] = n
        clean[key] = entry
    return clean


def save(body: dict) -> None:
    """Any of prices, currency and autoremove. The prices replace the saved
    ones: the page sends its whole table, and a price cleared there is gone."""
    with _lock:
        if "prices" in body:
            _store(PRICES, clean_prices(body.get("prices")))
        if "currency" in body:
            auth.set_setting(CURRENCY, str(body.get("currency") or "EUR").strip()[:12] or "EUR")
        if "autoremove" in body:
            auth.set_setting(AUTOREMOVE, "1" if body.get("autoremove") is True else "0")
