"""Python-side behavioral detection engine for the live watcher.

The Velociraptor detector artifacts (Custom.Atlas.*) each fire on a *single*
anomalous row — a new process, a new outbound connection. That misses
behaviors that only show up across *many* rows: a spawn burst, a connection
fan-out, a first-seen binary, a rare parent→child pair. Expressing those in VQL
would mean stateful server-side queries; instead we score them here, in the
watcher process, as rows stream past.

``BehaviorEngine.observe(detector, row)`` is called **pre-dedup** for every row
the watcher parses and returns zero or more ``SyntheticAlert``s. Those flow
through the watcher's existing ``_write_alert`` under a ``Behavior.*`` detector
name — the alert-waiter / check_alerts / start_investigation path is
detector-name-agnostic, so nothing downstream changes.

Stdlib-only: the standalone watcher imports this. The clock is injectable so
tests can drive sliding windows deterministically.
"""
from __future__ import annotations

import json
import math
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Optional

# Detector artifact names this engine reacts to, grouped by row shape.
_PROCESS_DETECTORS = {"Custom.Atlas.NewProcess", "Custom.Atlas.WinNewProcess"}
_NETWORK_DETECTORS = {"Custom.Atlas.NewNetwork", "Custom.Atlas.WinNewNetwork"}
_DNS_DETECTORS = {"Custom.Atlas.WinDnsQuery"}
_AUTH_DETECTORS = {"Custom.Atlas.AuthFailures", "Custom.Atlas.WinAuthFailures"}

# Conservative defaults — tuned to not fire on a quiet host. Overridable via
# monitoring/config.json (see load_config).
_DEFAULTS = {
    "enabled": True,
    "dedup_bucket_seconds": 600,
    "spawn_burst": {"window_seconds": 60, "threshold": 8},
    "conn_fanout": {"window_seconds": 60, "threshold": 12},
    "first_seen_binary": {"enabled": True},
    "rare_parent_child": {
        "suspicious_parents": [
            "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
            "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
            "w3wp.exe", "httpd", "nginx", "apache2", "sshd",
        ],
    },
    "dns_anomaly": {"window_seconds": 60, "burst_threshold": 50,
                    "entropy_threshold": 3.5, "min_label_length": 10},
    "auth_burst": {"window_seconds": 60, "threshold": 10},
}


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string — high on DGA-style labels."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def load_config(path: Optional[str] = None) -> dict:
    """Load the behavior config, merged over defaults. Missing file → defaults."""
    cfg = json.loads(json.dumps(_DEFAULTS))  # deep copy
    if not path or not os.path.isfile(path):
        return cfg
    try:
        with open(path) as fh:
            raw = json.load(fh) or {}
    except (OSError, json.JSONDecodeError, ValueError):
        return cfg
    behavior = raw.get("behavior", raw) if isinstance(raw, dict) else {}
    for k, v in behavior.items():
        if isinstance(v, dict) and isinstance(cfg.get(k), dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    return cfg


@dataclass
class SyntheticAlert:
    """A behavior-rule hit. ``row`` is the enriched evidence written verbatim
    into the alert's ``evidence`` field by the watcher."""
    detector: str          # e.g. "Behavior.SpawnBurst"
    row: dict = field(default_factory=dict)


def _g(row: dict, *keys: str) -> str:
    for k in keys:
        v = row.get(k)
        if v not in (None, ""):
            return str(v)
    return ""


def _basename(val: str) -> str:
    if not val:
        return ""
    return val.replace("\\", "/").rstrip("/").split("/")[-1]


class BehaviorEngine:
    """Stateful, thread-safe scoring of streamed detector rows.

    baseline: the client baseline dict (parent_child_pairs, optional
              image_hashes) used to decide what is "known-good".
    config:   see load_config().
    now_fn:   injectable clock (seconds) for deterministic tests.
    """

    def __init__(self, config: Optional[dict] = None,
                 baseline: Optional[dict] = None,
                 now_fn: Callable[[], float] = time.time):
        self.cfg = config or load_config()
        self.now = now_fn
        self._lock = threading.Lock()

        baseline = baseline or {}
        self._known_pairs = set(baseline.get("parent_child_pairs") or [])
        self._seen_hashes = set(baseline.get("image_hashes") or [])

        # Sliding-window state.
        self._spawn: dict[tuple, deque] = defaultdict(deque)
        self._conn: dict[tuple, deque] = defaultdict(deque)
        self._dns: dict[tuple, deque] = defaultdict(deque)
        self._auth: dict[tuple, deque] = defaultdict(deque)
        # Dedup ledger: (rule, entity, bucket) already emitted.
        self._emitted: set[tuple] = set()

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get("enabled", True))

    def observe(self, detector: str, row: dict) -> list[SyntheticAlert]:
        """Score one row. Returns novel behavior alerts (already deduped)."""
        if not self.enabled or not isinstance(row, dict):
            return []
        with self._lock:
            if detector in _PROCESS_DETECTORS:
                return self._on_process(row)
            if detector in _NETWORK_DETECTORS:
                return self._on_network(row)
            if detector in _DNS_DETECTORS:
                return self._on_dns(row)
            if detector in _AUTH_DETECTORS:
                return self._on_auth(row)
            return []

    # ── dedup ────────────────────────────────────────────────────────────────
    def _fresh(self, rule: str, entity: str) -> bool:
        """True (and records) the first time (rule, entity) is seen this bucket."""
        bucket = int(self.now() // int(self.cfg.get("dedup_bucket_seconds", 600) or 600))
        key = (rule, entity, bucket)
        if key in self._emitted:
            return False
        self._emitted.add(key)
        return True

    @staticmethod
    def _prune(dq: deque, cutoff: float) -> None:
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    # ── process rules ──────────────────────────────────────────────────────────
    def _on_process(self, row: dict) -> list[SyntheticAlert]:
        alerts: list[SyntheticAlert] = []
        now = self.now()
        host = _g(row, "Hostname", "hostname")
        child = _basename(_g(row, "process_name", "image_path"))
        parent = _basename(_g(row, "parent_image", "ParentName", "ppid", "Ppid"))

        # SpawnBurst — many process creations under one parent in a window.
        sb = self.cfg.get("spawn_burst", {})
        win = float(sb.get("window_seconds", 60))
        thr = int(sb.get("threshold", 8))
        key = (host, parent or "?")
        dq = self._spawn[key]
        dq.append((now, child))
        self._prune(dq, now - win)
        if len(dq) >= thr and self._fresh("SpawnBurst", f"{host}:{parent}"):
            alerts.append(SyntheticAlert("Behavior.SpawnBurst", {
                **row, "behavior_rule": "SpawnBurst",
                "entity": parent or "?", "observed": len(dq), "threshold": thr,
                "window_seconds": win,
            }))

        # FirstSeenBinary — a SHA256 not seen before (gated on hash presence).
        if self.cfg.get("first_seen_binary", {}).get("enabled", True):
            sha = _g(row, "sha256", "SHA256", "Sha256")
            if sha and sha not in self._seen_hashes:
                self._seen_hashes.add(sha)
                if self._fresh("FirstSeenBinary", sha):
                    alerts.append(SyntheticAlert("Behavior.FirstSeenBinary", {
                        **row, "behavior_rule": "FirstSeenBinary",
                        "entity": sha, "observed": _g(row, "image_path"),
                    }))

        # RareParentChild — unseen pair whose parent is a curated LOLBin-ish spawner.
        if parent and child:
            pair = f"{parent}>{child}"
            suspicious = {p.lower() for p in
                          self.cfg.get("rare_parent_child", {}).get("suspicious_parents", [])}
            if (pair not in self._known_pairs and parent.lower() in suspicious
                    and self._fresh("RareParentChild", pair)):
                alerts.append(SyntheticAlert("Behavior.RareParentChild", {
                    **row, "behavior_rule": "RareParentChild",
                    "entity": pair, "observed": pair,
                }))
        return alerts

    # ── network rule ───────────────────────────────────────────────────────────
    def _on_network(self, row: dict) -> list[SyntheticAlert]:
        now = self.now()
        host = _g(row, "Hostname", "hostname")
        pid = _g(row, "Pid", "pid")
        remote = _g(row, "remote_ip")
        if not remote:
            return []
        cf = self.cfg.get("conn_fanout", {})
        win = float(cf.get("window_seconds", 60))
        thr = int(cf.get("threshold", 12))
        key = (host, pid or "?")
        dq = self._conn[key]
        dq.append((now, remote))
        self._prune(dq, now - win)
        distinct = {ip for _, ip in dq}
        if len(distinct) >= thr and self._fresh("ConnFanout", f"{host}:{pid}"):
            return [SyntheticAlert("Behavior.ConnFanout", {
                **row, "behavior_rule": "ConnFanout",
                "entity": pid or "?", "observed": len(distinct), "threshold": thr,
                "window_seconds": win,
            })]
        return []

    # ── DNS rule ───────────────────────────────────────────────────────────────
    def _on_dns(self, row: dict) -> list[SyntheticAlert]:
        alerts: list[SyntheticAlert] = []
        now = self.now()
        host = _g(row, "Hostname", "hostname")
        pid = _g(row, "pid", "Pid")
        query = _g(row, "query_name", "QueryName")
        if not query:
            return []
        da = self.cfg.get("dns_anomaly", {})

        # High-entropy first label → DGA-like domain.
        first_label = query.split(".")[0]
        min_len = int(da.get("min_label_length", 10))
        ent_thr = float(da.get("entropy_threshold", 3.5))
        if len(first_label) >= min_len:
            entropy = round(_shannon_entropy(first_label), 2)
            if entropy >= ent_thr and self._fresh("DnsAnomaly", query):
                alerts.append(SyntheticAlert("Behavior.DnsAnomaly", {
                    **row, "behavior_rule": "DnsAnomaly", "reason": "high_entropy",
                    "entity": query, "observed": entropy, "threshold": ent_thr,
                }))

        # Per-process query burst → beaconing / tunneling.
        win = float(da.get("window_seconds", 60))
        burst = int(da.get("burst_threshold", 50))
        key = (host, pid or "?")
        dq = self._dns[key]
        dq.append((now, query))
        self._prune(dq, now - win)
        if len(dq) >= burst and self._fresh("DnsBurst", f"{host}:{pid}"):
            alerts.append(SyntheticAlert("Behavior.DnsAnomaly", {
                **row, "behavior_rule": "DnsAnomaly", "reason": "query_burst",
                "entity": pid or "?", "observed": len(dq), "threshold": burst,
                "window_seconds": win,
            }))
        return alerts

    # ── Auth-burst rule ────────────────────────────────────────────────────────
    def _on_auth(self, row: dict) -> list[SyntheticAlert]:
        now = self.now()
        host = _g(row, "Hostname", "hostname")
        src = _g(row, "source_ip", "SourceIp", "IpAddress")
        if not src:
            return []
        ab = self.cfg.get("auth_burst", {})
        win = float(ab.get("window_seconds", 60))
        thr = int(ab.get("threshold", 10))
        key = (host, src)
        dq = self._auth[key]
        dq.append((now, _g(row, "user")))
        self._prune(dq, now - win)
        if len(dq) >= thr and self._fresh("AuthBurst", f"{host}:{src}"):
            return [SyntheticAlert("Behavior.AuthBurst", {
                **row, "behavior_rule": "AuthBurst", "entity": src,
                "observed": len(dq), "threshold": thr, "window_seconds": win,
            })]
        return []
