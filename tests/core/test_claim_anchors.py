"""What a finding is anchored on for the citation checks: builds count like
dates, the case's own path and the universal signer name do not."""
from core.evidence_resolver import _claim_anchors, _shares_anchor


def test_a_build_number_is_an_anchor():
    anchors = _claim_anchors({"statement": "DC01 runs Windows Server 2016 (10.0.14393)"})
    assert "10.0.14393" in anchors
    assert _shares_anchor('"Major/Minor": "15.9600"', anchors) is False
    assert _shares_anchor("NT 10.0.14393 build", anchors) is True


def test_atlas_directories_and_the_signer_name_are_not_anchors():
    anchors = _claim_anchors({
        "statement": ("file analysis/dc01_fs/x.csv under exports shows entries "
                      "signed by Microsoft Corporation; file evidence/a.E01")})
    for junk in ("analysis", "exports", "corporation", "evidence"):
        assert junk not in anchors


def test_the_active_cases_own_path_words_are_not_anchors(monkeypatch, tmp_path):
    case = tmp_path / "CASE-r1-1"
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(case))
    anchors = _claim_anchors({"statement": f"named CASE-r1-1 in {case}/analysis/out.csv"})
    assert "case-r1-1" not in anchors


def test_a_cue_followed_by_grammar_names_nothing():
    """"the service were both deployed" and "the service binary x.exe" used to
    anchor a finding on "were" and "binary", identifiers no tool output can
    contain, so the finding could never be cited."""
    anchors = _claim_anchors({"statement": (
        "The PowerShell execution and the updater.exe service were both deployed "
        "by the same actor; the service binary svc_update.exe was found running")})
    assert "were" not in anchors and "binary" not in anchors and "running" not in anchors
    assert "svc_update.exe" in anchors


def test_a_chain_of_cues_still_names_the_thing():
    anchors = _claim_anchors({"statement": "the user account jdoe logged on; process named helper.exe"})
    assert {"jdoe", "helper.exe"} <= anchors


def test_the_event_id_shorthand_is_an_anchor():
    anchors = _claim_anchors({"statement": "4 successful RDP logons (EID 4624 LogonType 10)"})
    assert "4624" in anchors
    assert _shares_anchor("EventId,4624,10,...", anchors)


def test_a_build_number_inside_an_address_is_not_a_second_anchor():
    """"194.61.24.102" used to yield "61.24.102" as well: a tail no output
    prints on its own, so the finding could never be cited."""
    anchors = _claim_anchors({"statement": "beaconing to 194.61.24.102 over 443"})
    assert "194.61.24.102" in anchors
    assert "61.24.102" not in anchors


def test_prose_after_a_cue_is_not_an_anchor():
    anchors = _claim_anchors({"statement": (
        "the compromised Administrator account throughout; the beacon deployment "
        "and the malware family were confirmed")})
    assert "throughout" not in anchors and "deployment" not in anchors
    assert "family" not in anchors


def test_only_identifier_shaped_names_can_demand_a_citation():
    """Every anchor may satisfy a citation; a plain lower-case word after a
    cue ("process migration") cannot demand one - nothing forensic prints
    it, so demanding it refuses every citation."""
    node = {"statement": "process migration into the service svc_update.exe by account jdoe"}
    assert {"migration", "svc_update.exe", "jdoe"} <= _claim_anchors(node)
    assert _claim_anchors(node, demanding=True) == {"svc_update.exe"}


def test_a_malware_class_cue_names_the_family():
    anchors = _claim_anchors({"statement": "the beacon Cobalt Strike was staged; trojan Emotet ran"})
    assert {"cobalt", "emotet"} <= anchors
    assert _claim_anchors({"statement": "the beacon Cobalt Strike was staged"},
                          demanding=True) == {"cobalt"}
