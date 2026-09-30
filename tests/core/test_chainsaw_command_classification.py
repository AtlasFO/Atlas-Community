"""A chainsaw command that hunts an $MFT for names (misc.mft_rule_hunt) reads
no event log. Every classifier of executed command lines must see that, and
must still count a Sigma hunt over event logs as event-log work."""
from __future__ import annotations

import re

import pytest

MFT_HUNT = ("/usr/local/bin/chainsaw --no-banner hunt /case/evidence/WS01/$MFT -r "
            "/usr/local/share/chainsaw/rules/mft --load-unknown --skip-errors --jsonl "
            "--output /case/analysis/mft/mft_rule_hunt_MFT_0a1b2c3d.jsonl")
SIGMA_HUNT = ("/usr/local/bin/chainsaw hunt /case/evidence/WS01/winevt/Logs -s "
              "/usr/local/share/chainsaw/sigma --mapping "
              "/usr/local/share/chainsaw/mappings/sigma-event-logs-all.yml")


def _classifiers() -> dict:
    from core.auth_ontology import logon_inventory_cmd_regex
    from core.eventlog_layout import EVTX
    from tools._gates.critical_scan_timeout import _ALT_AUTH_TOOL_RE
    from tools._gates.temporal_negative_grounding import _ARTIFACT_CLASSES
    return {
        "eventlog_layout search": re.compile(EVTX.search, re.IGNORECASE),
        "eventlog_layout security_search": re.compile(EVTX.security_search, re.IGNORECASE),
        "logon inventory": logon_inventory_cmd_regex(),
        "critical scan alternative": _ALT_AUTH_TOOL_RE,
        "temporal gate event logs": dict(_ARTIFACT_CLASSES)["event logs"],
    }


@pytest.mark.parametrize("name", sorted(_classifiers()))
def test_an_mft_hunt_is_not_event_log_work(name):
    rx = _classifiers()[name]
    assert not rx.search(MFT_HUNT)
    assert rx.search(SIGMA_HUNT)
