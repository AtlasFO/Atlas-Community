"""Verdict-language lint and validation for client environment baselines."""

from core.brain import environment


def test_verdict_hits_flags_judgment_vocabulary():
    text = ("The host was compromised by the attacker's C2; a webshell "
            "provided persistence mechanism and lateral movement followed, "
            "then exfiltration of the IOC list.")
    hits = environment.verdict_hits(text)
    for word in ("compromised", "attacker", "c2", "webshell",
                 "persistence mechanism", "lateral movement", "exfiltration",
                 "ioc"):
        assert any(word in h for h in hits), (word, hits)


def test_verdict_hits_ignores_benign_operational_language():
    text = ("Administrators connect via JUMP01 using RDP; remote access "
            "tooling used by IT includes AnyDesk. Domain controllers are "
            "DC01/DC02; EC2 instances host the SIEM. Backups run nightly "
            "under svc.backup01.")
    assert environment.verdict_hits(text) == []


def test_verdict_hits_empty_and_none():
    assert environment.verdict_hits("") == []
    assert environment.verdict_hits(None) == []


def test_is_environment_destination():
    assert environment.is_environment_destination("wiki/environments")
    assert environment.is_environment_destination("wiki/environments/acme")
    assert environment.is_environment_destination("./wiki/environments/acme")
    assert not environment.is_environment_destination("wiki/concepts")
    assert not environment.is_environment_destination("memory/MEMORY.md")


def test_validate_clean_baseline_passes():
    meta = {"client": "acme-corp", "last_verified": "2026-07-01",
            "source": {"type": "client_provided"}}
    assert environment.validate(meta, "DC01 is the primary DC.") == []


def test_validate_rejects_agent_run_source():
    meta = {"client": "acme-corp", "last_verified": "2026-07-01",
            "source": {"type": "agent_run"}}
    problems = environment.validate(meta, "DC01 is the primary DC.")
    assert any("agent_run" in p for p in problems)


def test_validate_collects_all_problems():
    problems = environment.validate({}, "the attacker used a backdoor")
    joined = " ".join(problems)
    assert "source.type" in joined
    assert "client" in joined
    assert "last_verified" in joined
    assert "verdict language" in joined
