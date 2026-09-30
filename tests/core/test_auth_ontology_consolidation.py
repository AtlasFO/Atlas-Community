"""Executable auth markers must come from auth_ontology (no drift)."""
from __future__ import annotations

import re

from core.auth_ontology import (
    WINDOWS_AUTH_FAILURE_EIDS,
    WINDOWS_AUTH_SUCCESS_EIDS,
    auth_tool_hint_regex,
    case_session_auth_intent_regex,
    critical_auth_scan_regex,
    logon_inventory_cmd_regex,
    principal_appearance_cue_regex,
    principal_interactive_auth_cue_regex,
    session_evidence_regex,
    windows_auth_eids_prose,
)


def test_gates_and_reasoning_use_ontology_regexes():
    from tools._gates import principal_attribution_grounding as pag
    from tools._gates import critical_scan_timeout as cst
    from tools import dair

    assert pag._SESSION_RE.pattern == session_evidence_regex().pattern
    assert cst._CRITICAL_SCAN_RE.pattern == critical_auth_scan_regex().pattern
    assert (
        dair._PRINCIPAL_INTERACTIVE_AUTH_CUE_RE.pattern
        == principal_interactive_auth_cue_regex().pattern
    )
    assert (
        dair._PRINCIPAL_APPEARANCE_CUE_RE.pattern
        == principal_appearance_cue_regex().pattern
    )


def test_evidence_resolver_auth_components_use_ontology_eids():
    from core.auth_ontology import (
        WINDOWS_AUTH_BRUTE_EIDS,
        WINDOWS_AUTH_FAILURE_EIDS,
        WINDOWS_AUTH_RELATED_EIDS,
        WINDOWS_AUTH_SUCCESS_EIDS,
    )
    from core import evidence_resolver as er

    auth_pat = dict(er._COMPONENT_PATTERNS)["authentication"]
    brute_pat = dict(er._COMPONENT_PATTERNS)["brute_force"]
    for eid in WINDOWS_AUTH_RELATED_EIDS:
        assert auth_pat.search(f"Security EID {eid}")
    assert auth_pat.search(f"EID {WINDOWS_AUTH_SUCCESS_EIDS[0]}")
    for eid in WINDOWS_AUTH_BRUTE_EIDS:
        assert brute_pat.search(f"password spray {eid}")
    for eid in WINDOWS_AUTH_FAILURE_EIDS:
        assert eid in er._AUTH_WIDEN_LOCATOR_TOKENS
    for eid in WINDOWS_AUTH_BRUTE_EIDS:
        assert eid in er._AUTH_WIDEN_LOCATOR_TOKENS


def test_obligations_intent_uses_ontology():
    from core.investigation_obligations import _AUTH_SESSION_RE
    assert _AUTH_SESSION_RE.pattern == case_session_auth_intent_regex().pattern
    assert _AUTH_SESSION_RE.search("reconstruct logon sessions")
    assert _AUTH_SESSION_RE.search(f"EID {WINDOWS_AUTH_SUCCESS_EIDS[0]}")


def test_prose_helpers_track_ontology_tuples():
    prose = windows_auth_eids_prose()
    for eid in WINDOWS_AUTH_SUCCESS_EIDS + WINDOWS_AUTH_FAILURE_EIDS:
        assert eid in prose


def test_logon_inventory_and_tool_hint_cover_platform_eids():
    inv = logon_inventory_cmd_regex()
    hint = auth_tool_hint_regex()
    cmd = f"ez.evtxecmd --inc {WINDOWS_AUTH_SUCCESS_EIDS[0]},{WINDOWS_AUTH_FAILURE_EIDS[0]}"
    assert inv.search(cmd)
    assert hint.search(f"pull {WINDOWS_AUTH_SUCCESS_EIDS[0]} by logon type")
    # Not a parallel hardcoded list — still matches Linux session tools.
    assert inv.search("last -f /var/log/wtmp")
