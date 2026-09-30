"""Increment 6 (T1-3) — behavioral detection engine.

Pure-unit tests: feed row sequences through BehaviorEngine with a fake clock and
assert synthetic alerts (SpawnBurst / ConnFanout / FirstSeenBinary /
RareParentChild), window expiry, the dedup bucket, and the kill switch.
"""
import pytest

from monitoring import behavior, detectors


class _Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def tick(self, dt):
        self.t += dt
        return self.t


def _proc_row(**kw):
    row = {"Hostname": "host1", "process_name": "cmd.exe", "image_path": "C:\\cmd.exe",
           "pid": "10", "parent_image": "C:\\Windows\\explorer.exe"}
    row.update(kw)
    return row


def _net_row(**kw):
    row = {"Hostname": "host1", "pid": "50", "remote_ip": "8.8.8.8", "remote_port": 443}
    row.update(kw)
    return row


class TestSpawnBurst:
    def test_fires_at_threshold(self):
        clk = _Clock()
        cfg = behavior.load_config()
        cfg["spawn_burst"] = {"window_seconds": 60, "threshold": 5}
        eng = behavior.BehaviorEngine(config=cfg, now_fn=clk)
        alerts = []
        for i in range(4):
            clk.tick(1)
            alerts += eng.observe("Custom.Atlas.NewProcess",
                                  _proc_row(parent_image="/usr/bin/bash", process_name=f"p{i}"))
        assert alerts == []            # below threshold
        clk.tick(1)
        alerts += eng.observe("Custom.Atlas.NewProcess",
                              _proc_row(parent_image="/usr/bin/bash", process_name="p5"))
        assert len(alerts) == 1
        a = alerts[0]
        assert a.detector == "Behavior.SpawnBurst"
        assert a.row["observed"] == 5 and a.row["threshold"] == 5

    def test_window_expiry_prevents_fire(self):
        clk = _Clock()
        cfg = behavior.load_config()
        cfg["spawn_burst"] = {"window_seconds": 10, "threshold": 3}
        eng = behavior.BehaviorEngine(config=cfg, now_fn=clk)
        out = []
        for _ in range(2):
            out += eng.observe("Custom.Atlas.NewProcess", _proc_row(parent_image="bash"))
            clk.tick(20)               # each spawn ages out before the next
        out += eng.observe("Custom.Atlas.NewProcess", _proc_row(parent_image="bash"))
        assert out == []


class TestConnFanout:
    def test_distinct_ip_fanout(self):
        clk = _Clock()
        cfg = behavior.load_config()
        cfg["conn_fanout"] = {"window_seconds": 60, "threshold": 3}
        eng = behavior.BehaviorEngine(config=cfg, now_fn=clk)
        out = []
        for ip in ("1.1.1.1", "2.2.2.2"):
            out += eng.observe("Custom.Atlas.NewNetwork", _net_row(remote_ip=ip))
        assert out == []
        out += eng.observe("Custom.Atlas.NewNetwork", _net_row(remote_ip="3.3.3.3"))
        assert len(out) == 1 and out[0].detector == "Behavior.ConnFanout"
        assert out[0].row["observed"] == 3

    def test_same_ip_repeated_does_not_fan_out(self):
        cfg = behavior.load_config()
        cfg["conn_fanout"] = {"window_seconds": 60, "threshold": 3}
        eng = behavior.BehaviorEngine(config=cfg, now_fn=_Clock())
        out = []
        for _ in range(10):
            out += eng.observe("Custom.Atlas.NewNetwork", _net_row(remote_ip="9.9.9.9"))
        assert out == []               # one distinct IP, never fans out


class TestFirstSeenBinary:
    def test_first_hash_fires_once(self):
        eng = behavior.BehaviorEngine(config=behavior.load_config(), now_fn=_Clock())
        a = eng.observe("Custom.Atlas.WinNewProcess", _proc_row(sha256="deadbeef"))
        assert len(a) == 1 and a[0].detector == "Behavior.FirstSeenBinary"
        # Same hash again → no re-alert.
        a2 = eng.observe("Custom.Atlas.WinNewProcess", _proc_row(sha256="deadbeef"))
        assert a2 == []

    def test_hash_in_baseline_is_not_flagged(self):
        eng = behavior.BehaviorEngine(config=behavior.load_config(),
                                      baseline={"image_hashes": ["knownhash"]},
                                      now_fn=_Clock())
        assert eng.observe("Custom.Atlas.WinNewProcess", _proc_row(sha256="knownhash")) == []

    def test_no_hash_no_alert(self):
        eng = behavior.BehaviorEngine(config=behavior.load_config(), now_fn=_Clock())
        # Row without sha256 must not fire (gated on hash presence).
        out = [x for x in eng.observe("Custom.Atlas.NewProcess", _proc_row())
               if x.detector == "Behavior.FirstSeenBinary"]
        assert out == []


class TestRareParentChild:
    def test_suspicious_parent_unseen_pair_fires(self):
        eng = behavior.BehaviorEngine(config=behavior.load_config(), now_fn=_Clock())
        a = [x for x in eng.observe("Custom.Atlas.WinNewProcess",
                                    _proc_row(parent_image="C:\\...\\winword.exe",
                                              process_name="powershell.exe"))
             if x.detector == "Behavior.RareParentChild"]
        assert len(a) == 1
        assert a[0].row["entity"] == "winword.exe>powershell.exe"

    def test_known_pair_not_flagged(self):
        eng = behavior.BehaviorEngine(
            config=behavior.load_config(),
            baseline={"parent_child_pairs": ["winword.exe>powershell.exe"]},
            now_fn=_Clock())
        a = [x for x in eng.observe("Custom.Atlas.WinNewProcess",
                                    _proc_row(parent_image="winword.exe",
                                              process_name="powershell.exe"))
             if x.detector == "Behavior.RareParentChild"]
        assert a == []

    def test_benign_parent_not_flagged(self):
        eng = behavior.BehaviorEngine(config=behavior.load_config(), now_fn=_Clock())
        a = [x for x in eng.observe("Custom.Atlas.WinNewProcess",
                                    _proc_row(parent_image="explorer.exe",
                                              process_name="notepad.exe"))
             if x.detector == "Behavior.RareParentChild"]
        assert a == []                 # explorer not in suspicious-parent list


class TestDedupAndKillSwitch:
    def test_dedup_bucket_suppresses_repeat(self):
        clk = _Clock()
        cfg = behavior.load_config()
        cfg["conn_fanout"] = {"window_seconds": 3600, "threshold": 2}
        cfg["dedup_bucket_seconds"] = 600
        eng = behavior.BehaviorEngine(config=cfg, now_fn=clk)
        eng.observe("Custom.Atlas.NewNetwork", _net_row(remote_ip="1.1.1.1"))
        first = eng.observe("Custom.Atlas.NewNetwork", _net_row(remote_ip="2.2.2.2"))
        assert len(first) == 1
        # Still same 10-min bucket + same entity → suppressed.
        clk.tick(60)
        again = eng.observe("Custom.Atlas.NewNetwork", _net_row(remote_ip="3.3.3.3"))
        assert again == []
        # Next bucket → fires again.
        clk.tick(600)
        later = eng.observe("Custom.Atlas.NewNetwork", _net_row(remote_ip="4.4.4.4"))
        assert len(later) == 1

    def test_kill_switch(self):
        cfg = behavior.load_config()
        cfg["enabled"] = False
        cfg["spawn_burst"] = {"window_seconds": 60, "threshold": 1}
        eng = behavior.BehaviorEngine(config=cfg, now_fn=_Clock())
        assert eng.observe("Custom.Atlas.NewProcess", _proc_row()) == []

    def test_unknown_detector_ignored(self):
        eng = behavior.BehaviorEngine(config=behavior.load_config(), now_fn=_Clock())
        assert eng.observe("Custom.Atlas.YaraProcess", {"pid": 1}) == []


class TestConfigLoading:
    def test_defaults_when_missing(self, tmp_path):
        cfg = behavior.load_config(str(tmp_path / "nope.json"))
        assert cfg["enabled"] is True
        assert cfg["spawn_burst"]["threshold"] == 8

    def test_merges_over_defaults(self, tmp_path):
        p = tmp_path / "config.json"
        p.write_text('{"behavior": {"spawn_burst": {"threshold": 3}}}')
        cfg = behavior.load_config(str(p))
        assert cfg["spawn_burst"]["threshold"] == 3
        assert cfg["spawn_burst"]["window_seconds"] == 60   # default preserved


class TestSyntheticRegistry:
    def test_watcher_helpers_render_behavior_alerts(self):
        # _write_alert in the watcher uses these registry lookups; they must
        # produce clean summaries/severity for Behavior.* (not JSON fallback).
        s = detectors.summarize_row("Behavior.SpawnBurst",
                                    {"observed": 9, "entity": "bash",
                                     "threshold": 8, "window_seconds": 60})
        assert "spawn burst" in s.lower() and "bash" in s
        assert detectors.severity_of("Behavior.ConnFanout") == "high"
        assert detectors.pivots_for("Behavior.FirstSeenBinary")


# ── Increment 8: DNS anomaly + auth burst ────────────────────────────────────

class TestDnsAnomaly:
    def test_high_entropy_label_fires(self):
        eng = behavior.BehaviorEngine(config=behavior.load_config(), now_fn=_Clock())
        a = [x for x in eng.observe("Custom.Atlas.WinDnsQuery",
                                    {"Hostname": "h", "pid": "5",
                                     "query_name": "kq7z9x2wm4pd8v.evil.com"})
             if x.detector == "Behavior.DnsAnomaly"]
        assert len(a) == 1
        assert a[0].row["reason"] == "high_entropy"
        assert a[0].row["entity"] == "kq7z9x2wm4pd8v.evil.com"

    def test_low_entropy_domain_no_fire(self):
        eng = behavior.BehaviorEngine(config=behavior.load_config(), now_fn=_Clock())
        a = [x for x in eng.observe("Custom.Atlas.WinDnsQuery",
                                    {"Hostname": "h", "pid": "5",
                                     "query_name": "www.google.com"})
             if x.detector == "Behavior.DnsAnomaly"]
        assert a == []

    def test_query_burst_fires(self):
        cfg = behavior.load_config()
        cfg["dns_anomaly"] = {"window_seconds": 60, "burst_threshold": 5,
                              "entropy_threshold": 99, "min_label_length": 99}
        eng = behavior.BehaviorEngine(config=cfg, now_fn=_Clock())
        out = []
        for i in range(5):
            out += eng.observe("Custom.Atlas.WinDnsQuery",
                               {"Hostname": "h", "pid": "7", "query_name": f"a{i}.example.com"})
        bursts = [x for x in out if x.row.get("reason") == "query_burst"]
        assert len(bursts) == 1 and bursts[0].row["observed"] == 5


class TestAuthBurst:
    def test_failures_from_one_ip_fire(self):
        cfg = behavior.load_config()
        cfg["auth_burst"] = {"window_seconds": 60, "threshold": 3}
        eng = behavior.BehaviorEngine(config=cfg, now_fn=_Clock())
        out = []
        for u in ("root", "admin", "test"):
            out += eng.observe("Custom.Atlas.AuthFailures",
                               {"Hostname": "h", "source_ip": "9.9.9.9", "user": u})
        assert len(out) == 1
        assert out[0].detector == "Behavior.AuthBurst"
        assert out[0].row["entity"] == "9.9.9.9" and out[0].row["observed"] == 3

    def test_spread_across_ips_no_burst(self):
        cfg = behavior.load_config()
        cfg["auth_burst"] = {"window_seconds": 60, "threshold": 3}
        eng = behavior.BehaviorEngine(config=cfg, now_fn=_Clock())
        out = []
        for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
            out += eng.observe("Custom.Atlas.WinAuthFailures",
                               {"Hostname": "h", "source_ip": ip, "user": "root"})
        assert out == []       # one failure per IP, no single-IP burst

    def test_no_source_ip_ignored(self):
        eng = behavior.BehaviorEngine(config=behavior.load_config(), now_fn=_Clock())
        assert eng.observe("Custom.Atlas.AuthFailures", {"user": "root"}) == []


class TestNewDetectorsRegistered:
    def test_dns_and_auth_detectors_present(self):
        assert "Custom.Atlas.WinDnsQuery" in detectors.detectors_for_platform("windows")
        assert "Custom.Atlas.AuthFailures" in detectors.detectors_for_platform("linux")
        assert "Custom.Atlas.WinAuthFailures" in detectors.detectors_for_platform("windows")

    def test_dns_is_windows_only(self):
        # No Linux DNS detector — documented gap.
        assert not any("Dns" in n for n in detectors.detectors_for_platform("linux"))
