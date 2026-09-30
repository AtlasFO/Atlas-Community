"""Tests for the interactive_injection_grounding gate (and the DEVICE_INITIAL_ACCESS
negative_completeness manifest).

HID/keystroke-injection law is opt-in via CASE intent or finding prose
(core.case_intents). When in scope, grounding requires misc.device_install_inventory
with coverage spanning the claim window and flagged_count == 0.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

from tools._gates import GateContext
from tools._gates import interactive_injection_grounding as iig
from tools._gates import negative_completeness as nc


# A successful structured inventory, nothing flagged. The markers (set by the MCP
# tool via annotate_tool_call, not fakeable in prose) are what the gates read.
_INVENTORY_CLEAN = {
    "type": "tool_call", "call_id": 4242, "success": True,
    "cmd": "misc.device_install_inventory /mnt/Windows/INF/setupapi.dev.log",
    "device_install_inventory": True,
    "coverage_window": {"start": "2031-01-02 07:00:00", "end": "2031-12-31 06:00:00"},
    "device_count": 12, "flagged_count": 0,
}
# Same inventory, but it flagged a keystroke-injector (a composite HID+storage device).
_INVENTORY_FLAGGED = {**_INVENTORY_CLEAN, "call_id": 4243, "flagged_count": 1}
# A keyword grep / strings dump — the RETIRED path; carries no inventory marker.
_STRINGS_GREP = {
    "type": "tool_call", "call_id": 99, "success": True,
    "cmd": "strings -a /mnt/Windows/INF/setupapi.dev.log",
    "stdout_excerpt": ">>>  [Device Install - USB\\VID_BEEF&PID_1234]\nHID\\VID_BEEF&PID_1234&MI_01",
}

# Finding prose that opts into HID-injection intent (claim-driven, not silent).
_HID = " (ruling out keystroke injection / BadUSB)"


def _ctx(description, cmds=None, *, tier="CONFIRMED", supporting_evidence="",
         tool_calls=None, by_call_id=None, input_call_ids=None, hid_intent=True):
    desc = description + (_HID if hid_intent and "keystroke" not in description.lower()
                          and "badusb" not in description.lower()
                          and "bad usb" not in description.lower()
                          and "hid inject" not in description.lower()
                          else "")
    entries = [{"type": "tool_call", "cmd": c} for c in (cmds or [])]
    entries += list(tool_calls or [])
    by_type = {"tool_call": entries, "dair_call": [], "investigation_narration": []}
    return GateContext(
        description=desc,
        confidence=tier.capitalize(),
        tier=tier,
        source="test",
        linked_call_id=0,
        tested_hypothesis_id="",
        log=MagicMock(**{"case_dir.return_value": None}),
        idx=SimpleNamespace(by_call_id=(by_call_id or {}), by_type=by_type),
        window=[],
        input_call_ids=(input_call_ids or []),
        supporting_evidence=supporting_evidence,
    )


class TestInteractiveInjectionGate:
    def test_without_hid_intent_usb_interactive_passes(self):
        # Removable media + interactive authorship alone must NOT enable BadUSB law.
        out = iig.check(_ctx(
            "Jane Doe, in a local interactive console session (LogonType 11), "
            "created the covert svc.example account",
            ["rip.pl -r SYSTEM -p usbstor"],
            hid_intent=False))
        assert out is None

    def test_interactive_account_creation_refused(self):
        out = iig.check(_ctx(
            "Jane Doe, in a local interactive console session (LogonType 11), "
            "created the covert svc.example account",
            ["rip.pl -r SYSTEM -p usbstor"]))
        assert out is not None
        assert out["gate"] == "interactive_injection_grounding"
        assert "device_install_inventory" in out["error"]

    def test_clean_inventory_clears(self):
        out = iig.check(_ctx(
            "Jane created the covert account in an interactive console session (type 11)",
            tool_calls=[_INVENTORY_CLEAN]))
        assert out is None

    def test_flagged_inventory_refuses_human_authorship(self):
        out = iig.check(_ctx(
            "Jane created the svc.example account in an interactive Type-11 console "
            "session on 2031-05-03 — human-authored, not injected",
            tool_calls=[_INVENTORY_FLAGGED]))
        assert out is not None
        assert out["gate"] == "interactive_injection_grounding"
        assert "flagged" in out["error"].lower()

    def test_strings_grep_does_not_satisfy(self):
        out = iig.check(_ctx(
            "Jane created the covert account in an interactive console session",
            ["rip.pl -p usbstor"], tool_calls=[_STRINGS_GREP]))
        assert out is not None
        assert out["gate"] == "interactive_injection_grounding"

    def test_prose_claim_without_inventory_refused(self):
        out = iig.check(_ctx(
            "Jane created the account in an interactive session",
            ["rip.pl -p usbstor"],
            supporting_evidence="setupapi.dev.log shows only mass-storage USB, no HID device"))
        assert out is not None
        assert out["gate"] == "interactive_injection_grounding"

    def test_input_call_id_to_inventory_clears(self):
        out = iig.check(_ctx(
            "Jane created the covert account in an interactive console session",
            ["rip.pl -p usbstor"],
            by_call_id={4242: _INVENTORY_CLEAN}, input_call_ids=[4242]))
        assert out is None

    def test_inventory_must_span_claim_window(self):
        out = iig.check(_ctx(
            "Jane created the covert account in an interactive console session on 2032-09-01",
            tool_calls=[_INVENTORY_CLEAN]))
        assert out is not None
        assert out["gate"] == "interactive_injection_grounding"

    def test_softened_session_attribution_refused(self):
        out = iig.check(_ctx(
            "A local administrator account 'svc.example' was created from the operator "
            "session (SubjectLogonId 0x1A2B3) and added to the Builtin\\Administrators group",
            ["rip.pl -r SYSTEM -p usbstor"], tier="LIKELY"))
        assert out is not None
        assert out["gate"] == "interactive_injection_grounding"

    def test_softened_session_attribution_clears_with_inventory(self):
        out = iig.check(_ctx(
            "A local administrator account 'svc.example' was created from the operator "
            "session (SubjectLogonId 0x1A2B3) and added to Builtin\\Administrators",
            tier="LIKELY", tool_calls=[_INVENTORY_CLEAN]))
        assert out is None

    def test_system_process_session_creation_passes(self):
        assert iig.check(_ctx(
            "services.exe created the service from the SYSTEM logon session",
            ["rip.pl -p usbstor"])) is None

    def test_no_removable_media_out_of_scope(self):
        assert iig.check(_ctx("Jane created the account in an interactive console session",
                              ["vol.pslist"])) is None

    def test_non_interactive_action_passes(self):
        assert iig.check(_ctx("Jane exfiltrated data to Dropbox",
                              ["rip.pl -p usbstor"])) is None

    def test_process_not_human_passes(self):
        assert iig.check(_ctx("explorer.exe created the Run key in an interactive session",
                              ["rip.pl -p usbstor"])) is None

    def test_suspected_tier_not_gated(self):
        assert iig.check(_ctx("Jane created the account interactively",
                              ["rip.pl -p usbstor"], tier="SUSPECTED")) is None

    def test_known_subject_via_trace_fires(self):
        by_type = {
            "tool_call": [{"type": "tool_call", "cmd": "rip.pl -p usbstor"}],
            "dair_call": [{"inputs": {"case_context": "Subject Sam on host host-01"},
                           "investigation_focus": ""}],
            "investigation_narration": [],
        }
        ctx = GateContext(
            description=(
                "Sam created the service in an interactive console session "
                "(ruling out keystroke injection)"
            ),
            confidence="Confirmed", tier="CONFIRMED", source="test", linked_call_id=0,
            tested_hypothesis_id="", log=MagicMock(**{"case_dir.return_value": None}),
            idx=SimpleNamespace(by_call_id={}, by_type=by_type), window=[],
            input_call_ids=[], supporting_evidence="")
        out = iig.check(ctx)
        assert out is not None and out["gate"] == "interactive_injection_grounding"


class TestDeviceInitialAccessManifest:
    """Absence claims that name BadUSB remain claim-driven (always gated)."""

    def test_no_badusb_negative_without_inventory_refused(self):
        out = nc.check(_ctx("No malicious USB or HID injection was found",
                            ["rip.pl -p usbstor"], tier="UNCONFIRMED", hid_intent=False))
        assert out is not None and out["gate"] == "negative_completeness"
        assert "device_install_inventory" in out["error"]

    def test_no_badusb_negative_with_clean_inventory_passes(self):
        out = nc.check(_ctx(
            "No HID injection / BadUSB: the device inventory shows no keystroke injector",
            tier="UNCONFIRMED", tool_calls=[_INVENTORY_CLEAN], hid_intent=False))
        assert out is None

    def test_no_badusb_negative_with_flagged_inventory_refused(self):
        out = nc.check(_ctx(
            "No BadUSB present in the 2031-05 window",
            tier="UNCONFIRMED", tool_calls=[_INVENTORY_FLAGGED], hid_intent=False))
        assert out is not None and out["gate"] == "negative_completeness"
        assert "flagged" in out["error"].lower()

    def test_no_badusb_negative_strings_grep_refused(self):
        out = nc.check(_ctx(
            "No HID injection / BadUSB: setupapi.dev.log shows only mass-storage",
            ["strings -a setupapi.dev.log", "rip.pl -r SYSTEM -p usbstor"],
            tier="UNCONFIRMED", tool_calls=[_STRINGS_GREP], hid_intent=False))
        assert out is not None and out["gate"] == "negative_completeness"

    def test_no_badusb_negative_absent_escape_passes(self):
        out = nc.check(_ctx(
            "No BadUSB assessment possible: setupapi.dev.log absent from evidence (not collected)",
            ["rip.pl -p usbstor"], tier="UNCONFIRMED", hid_intent=False))
        assert out is None
