#!/usr/bin/env python3
"""Atlas Velociraptor event-stream watcher.

Long-running sidecar that subscribes to Velociraptor's client monitoring
stream for the named Custom.Atlas.* artifacts and emits one alert JSON per
row into the case's alerts directory.

Usage (spawned detached by tools/monitor.py:start_watcher):

  atlas-velo-watcher \\
      --case-id DEMO-LIVE \\
      --client-id C.abc... \\
      --artifacts Custom.Atlas.NewProcess,Custom.Atlas.NewNetwork \\
      --alerts-dir /home/analyst/cases/DEMO-LIVE/monitoring/alerts

Each subscribed VQL is run as a separate ``velociraptor query --format=jsonl``
subprocess in a thread. Stdout lines are parsed as JSON and assembled into
the alert schema. ``_seq.txt`` is incremented under an fcntl lock so
concurrent detector threads never collide on the same seq.

Catch-all SIGTERM handler shuts the subprocesses down cleanly so the alert
queue is never left half-written.

No MCP imports — this runs as a standalone Python script.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

# Standalone script: put the repo root on the path so the stdlib-only detector
# registry (monitoring/detectors.py) is importable without installation.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from monitoring import detectors  # noqa: E402
from monitoring import behavior  # noqa: E402

VELO_BIN_DEFAULT = "velociraptor"
API_CONFIG_DEFAULT = os.path.expanduser(
    "~/.config/atlas/velociraptor/api.config.yaml"
)

# Detector metadata (pivots, dedup signature, summary, severity) now lives in
# the central registry `monitoring/detectors.py`, the single source of truth
# shared with tools/monitor.py and monitoring/render.py. Unknown detectors
# degrade to the registry's defaults, so an operator hand-pushing an artifact
# not in the table still gets alerts.
#
# For live-monitoring cases the canonical investigation substrate is
# `velo.collect_artifact(<artifact>)` against the same client the alert
# fired from, not `live.*` SSH calls. `live.*` requires the host to be
# registered in ~/cases/.common/live_hosts.json AND a working SSH path
# from SIFT to the victim — both are absent in the demo container by
# default. Use `live.*` only as a documented fallback when an operator
# has explicitly set up the SSH bridge.


# ── Per-detector dedup ──────────────────────────────────────────────────────
#
# Each detector polls on a fixed interval, so the SAME row keeps coming
# down the watch_monitoring stream every tick. The watcher de-duplicates by
# computing a stable "signature" per detector (the natural key of the
# event) and dropping rows whose signature has already been alerted on
# during this watcher's lifetime.
#
# Restarting the watcher clears the dedup cache. That matters: after
# stop_watcher/start_watcher, every still-present anomaly will refire once.
# This is intentional — operators kicking the watcher get a fresh view.

def _row_signature(detector: str, row: dict) -> str:
    """Stable key for dedup. Empty string means 'no signature — never dedup'."""
    return detectors.row_signature(detector, row)


# Cap on per-detector dedup memory. Old entries are evicted FIFO when
# the cache exceeds this size — see _MAX_DEDUP_ENTRIES_PER_DETECTOR.
_MAX_DEDUP_ENTRIES_PER_DETECTOR = 10_000

# detector → ordered dict-like set of signatures already alerted on.
# Plain dicts preserve insertion order in Python 3.7+, so this doubles
# as a FIFO eviction queue.
_seen_signatures: dict[str, dict[str, None]] = {}
_seen_lock = threading.Lock()


def _should_emit(detector: str, row: dict) -> bool:
    """Return True if this row should produce an alert (first time we've
    seen this signature for this detector in this watcher lifetime)."""
    sig = _row_signature(detector, row)
    if not sig:
        return True
    with _seen_lock:
        seen = _seen_signatures.setdefault(detector, {})
        if sig in seen:
            return False
        seen[sig] = None
        if len(seen) > _MAX_DEDUP_ENTRIES_PER_DETECTOR:
            # Pop oldest. dict iteration is insertion-ordered.
            oldest = next(iter(seen))
            del seen[oldest]
        return True

# Stop flag set by the SIGTERM handler.
_stop = threading.Event()


def _install_signal_handlers() -> None:
    def _handler(signum, _frame):
        print(f"[watcher] received signal {signum}, shutting down …", flush=True)
        _stop.set()
    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)


def _next_seq(alerts_dir: Path) -> int:
    """Atomically increment _seq.txt; return new value. fcntl-locked."""
    seq_file = alerts_dir / "_seq.txt"
    lock_file = alerts_dir / "_seq.lock"
    alerts_dir.mkdir(parents=True, exist_ok=True)
    with open(lock_file, "w") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            try:
                cur = int(seq_file.read_text().strip() or "0")
            except (OSError, ValueError):
                cur = 0
            cur += 1
            seq_file.write_text(str(cur))
            return cur
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _summarize_row(detector: str, row: dict) -> str:
    """One-line human description for the alert's `summary` field."""
    return detectors.summarize_row(detector, row)


def _severity(detector: str) -> str:
    return detectors.severity_of(detector)


def _write_alert(
    alerts_dir: Path,
    case_id: str,
    client_id: str,
    detector: str,
    row: dict,
) -> Path:
    seq = _next_seq(alerts_dir)
    alert_id = str(uuid.uuid4())
    alert = {
        "alert_id": alert_id,
        "seq": seq,
        "case_id": case_id,
        "client_id": client_id,
        "hostname": row.get("Hostname") or row.get("hostname"),
        "timestamp_utc": row.get("timestamp_utc") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "detector": detector,
        "severity": _severity(detector),
        "summary": _summarize_row(detector, row),
        "evidence": row,
        "suggested_pivot_tools": detectors.pivots_for(detector),
        "consumed": False,
    }
    safe_detector = detector.split(".")[-1]
    path = alerts_dir / f"{seq:08d}_{safe_detector}.json"
    path.write_text(json.dumps(alert, indent=2))
    print(f"[watcher] wrote alert {path.name}: {alert['summary'][:120]}", flush=True)
    return path


def _consume_detector(
    detector: str,
    client_id: str,
    case_id: str,
    alerts_dir: Path,
    velo_bin: str,
    api_config: str,
    engine: "behavior.BehaviorEngine | None" = None,
) -> None:
    """One thread per detector — owns its `velociraptor query` subprocess."""
    vql = (
        f"SELECT * FROM watch_monitoring(artifact={json.dumps(detector)}) "
        f"WHERE ClientId = {json.dumps(client_id)}"
    )
    argv = [velo_bin, "--api_config", api_config, "query", "--format", "jsonl", vql]
    print(f"[watcher][{detector}] starting: {shlex.join(argv)}", flush=True)
    while not _stop.is_set():
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as e:
            print(f"[watcher][{detector}] velociraptor binary not found: {e}", flush=True)
            return

        # Drain stderr on a separate thread so it doesn't block stdout.
        def _drain_stderr() -> None:
            assert proc.stderr is not None
            for line in proc.stderr:
                line = line.rstrip()
                if line:
                    print(f"[watcher][{detector}][stderr] {line}", flush=True)
        threading.Thread(target=_drain_stderr, daemon=True).start()

        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                if _stop.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    print(f"[watcher][{detector}] skipping non-JSON row: {line[:120]}", flush=True)
                    continue
                # Behavior scoring runs PRE-dedup on every row — a spawn burst is
                # made of rows the per-signature dedup would otherwise collapse.
                # The engine dedups its own output by rule+entity+bucket.
                if engine is not None:
                    try:
                        for sa in engine.observe(detector, row):
                            _write_alert(alerts_dir, case_id, client_id,
                                         sa.detector, sa.row)
                    except Exception as e:   # never let a rule bug kill the stream
                        print(f"[watcher][{detector}] behavior error: {e}", flush=True)
                if not _should_emit(detector, row):
                    # Already-seen signature for this detector in this
                    # watcher lifetime. Skip silently — logging every
                    # duplicate would blow up the log.
                    continue
                _write_alert(alerts_dir, case_id, client_id, detector, row)
        finally:
            if _stop.is_set():
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

        if _stop.is_set():
            return
        # Stream closed without us asking — server restart, network blip,
        # or velociraptor process exit. Wait a beat and re-subscribe.
        rc = proc.poll()
        print(f"[watcher][{detector}] subprocess exited rc={rc} — reconnecting in 5s", flush=True)
        time.sleep(5)


def main() -> int:
    parser = argparse.ArgumentParser(description="Atlas Velociraptor event-stream watcher")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--artifacts", required=True,
                        help="comma-separated Custom.Atlas.* artifact names")
    parser.add_argument("--alerts-dir", required=True)
    parser.add_argument("--velo-bin", default=os.environ.get("ATLAS_VELO_BIN") or VELO_BIN_DEFAULT)
    parser.add_argument("--api-config",
                        default=os.environ.get("ATLAS_VELO_API_CONFIG") or API_CONFIG_DEFAULT)
    parser.add_argument("--config", default=None,
                        help="behavior-engine config JSON (monitoring/config.json)")
    parser.add_argument("--baseline", default=None,
                        help="baseline JSON — seeds RareParentChild/FirstSeenBinary")
    args = parser.parse_args()

    detectors = [d.strip() for d in args.artifacts.split(",") if d.strip()]
    if not detectors:
        print("[watcher] no --artifacts given", file=sys.stderr)
        return 2

    alerts_dir = Path(args.alerts_dir)
    alerts_dir.mkdir(parents=True, exist_ok=True)

    if not Path(args.api_config).exists():
        print(f"[watcher] api_config not found: {args.api_config}", file=sys.stderr)
        return 3

    # Behavior engine (optional). Off when --config is absent or the config
    # kill-switch (behavior.enabled) is false — the watcher then behaves exactly
    # as before this feature landed.
    engine = None
    if args.config:
        cfg = behavior.load_config(args.config)
        if cfg.get("enabled", True):
            baseline_doc = {}
            if args.baseline and Path(args.baseline).exists():
                try:
                    baseline_doc = json.loads(Path(args.baseline).read_text())
                except (OSError, json.JSONDecodeError, ValueError):
                    baseline_doc = {}
            engine = behavior.BehaviorEngine(config=cfg, baseline=baseline_doc)
            print(f"[watcher] behavior engine enabled "
                  f"(rules: SpawnBurst/ConnFanout/FirstSeenBinary/RareParentChild)",
                  flush=True)

    _install_signal_handlers()

    threads: list[threading.Thread] = []
    for d in detectors:
        t = threading.Thread(
            target=_consume_detector,
            args=(d, args.client_id, args.case_id, alerts_dir, args.velo_bin,
                  args.api_config, engine),
            daemon=True,
            name=f"watch-{d}",
        )
        t.start()
        threads.append(t)

    print(f"[watcher] started {len(threads)} detector thread(s) "
          f"for case={args.case_id} client={args.client_id}", flush=True)

    while not _stop.is_set():
        time.sleep(1)
    for t in threads:
        t.join(timeout=10)
    print("[watcher] shut down cleanly", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
