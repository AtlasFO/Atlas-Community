"""Platform auth ontology — adapters, not case IOCs."""
from core.auth_ontology import (
    WINDOWS_AUTH_FAILURE_EIDS,
    WINDOWS_AUTH_SUCCESS_EIDS,
    positively_frames_success,
    session_search_cmd_regex,
    claim_auth_success_regex,
    claim_auth_none_regex,
)


def test_windows_eids_are_platform_adapters_not_empty():
    assert "4624" in WINDOWS_AUTH_SUCCESS_EIDS
    assert "4625" in WINDOWS_AUTH_FAILURE_EIDS


def test_session_search_cmd_matches_security_evtx():
    rx = session_search_cmd_regex()
    assert rx.search("EvtxECmd -f Security.evtx --inc 4624,4625")
    assert rx.search("security_logons export")


def test_claim_polarity_helpers():
    assert claim_auth_success_regex().search("3 successful network logons")
    assert claim_auth_none_regex().search("no successful authentication found")


def test_positively_frames_success():
    assert positively_frames_success("user successfully authenticated from host")
    assert not positively_frames_success("no successful logon was observed")
