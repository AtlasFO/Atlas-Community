"""Tests for generalized external_knowledge_grounding + enrich.oui_lookup."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tools._gates import GateContext
from tools._gates import external_knowledge_grounding as ekg

# enrich.oui_lookup reads the IEEE registry from disk (Debian/Ubuntu package
# "ieee-data"). It is deliberately offline — no API key, no internet — which
# also means the lookup cannot work where the package is absent. Skip instead
# of failing, so a missing OS package does not read as a code regression.
_OUI_PATHS = ("/usr/share/ieee-data/oui.txt", "/var/lib/ieee-data/oui.txt")
_OUI_AVAILABLE = any(Path(p).is_file() for p in _OUI_PATHS)
_OUI_SKIP_REASON = (
    "IEEE OUI registry not present at "
    + " or ".join(_OUI_PATHS)
    + " — install the 'ieee-data' package to run this test"
)


def _ctx(description, *, tier="CONFIRMED", supporting_evidence="",
         cmds=None):
    tool_calls = []
    by_call_id = {}
    for i, (cmd, excerpt) in enumerate(cmds or []):
        e = {
            "type": "tool_call",
            "cmd": cmd,
            "success": True,
            "call_id": i + 1,
            "stdout_excerpt": excerpt,
        }
        tool_calls.append(e)
        by_call_id[i + 1] = e
    return GateContext(
        description=description,
        confidence=tier.capitalize(),
        tier=tier,
        source="test",
        linked_call_id=1 if tool_calls else 0,
        tested_hypothesis_id="",
        log=MagicMock(),
        idx=SimpleNamespace(by_call_id=by_call_id,
                            by_type={"tool_call": tool_calls}),
        window=[],
        input_call_ids=[1] if tool_calls else [],
        supporting_evidence=supporting_evidence,
    )


class TestMacOui:
    def test_refused_without_lookup(self):
        ctx = _ctx(
            "MAC prefix B8:27:EB belongs to ExampleNet based on the OUI.",
            cmds=[("strings dhcp.log",
                   "DHCPDISCOVER from b8:27:eb:00:00:01 via eth0")],
        )
        fail = ekg.check(ctx)
        assert fail is not None
        assert fail.get("detail_gate") == "mac_oui_vendor"

    def test_usb_string_does_not_ground_oui(self):
        ctx = _ctx(
            "The OUI B8:27:EB is assigned to ExampleNet.",
            supporting_evidence="ExampleNet Composite Device|ExampleNet|00000001",
        )
        assert ekg.check(ctx) is not None

    def test_passes_with_oui_lookup(self):
        ctx = _ctx(
            "MAC prefix B8:27:EB belongs to Raspberry Pi Foundation per IEEE OUI.",
            supporting_evidence=(
                'enrich.oui_lookup {"organization":"Raspberry Pi Foundation",'
                '"registry":"IEEE MA-L","prefix_dashed":"B8-27-EB"}'
            ),
        )
        assert ekg.check(ctx) is None


class TestOtherExternalClasses:
    def test_ip_geo_refused(self):
        ctx = _ctx("IP 8.8.8.8 is located in the United States (ASN 15169).")
        fail = ekg.check(ctx)
        assert fail is not None
        assert fail.get("detail_gate") == "ip_geo_asn_reputation"

    def test_ip_geo_passes_with_vt(self):
        ctx = _ctx(
            "IP 8.8.8.8 is located in the United States.",
            supporting_evidence='enrich.vt_lookup_ip {"country":"US","asn":15169}',
        )
        assert ekg.check(ctx) is None

    def test_hash_family_refused(self):
        ctx = _ctx(
            "SHA256 deadbeef… is known malware family Emotet."
        )
        # Need a pattern that matches — use clearer text
        ctx = _ctx(
            "The SHA256 hash abcdef0123456789abcdef0123456789abcdef0123456789"
            "abcdef0123456789 is known malware identified as Emotet."
        )
        fail = ekg.check(ctx)
        assert fail is not None
        assert fail.get("detail_gate") == "hash_malware_family"

    def test_cve_refused_without_evidence(self):
        ctx = _ctx(
            "The intrusion exploited CVE-2024-12345 as the root cause."
        )
        fail = ekg.check(ctx)
        assert fail is not None
        assert fail.get("detail_gate") == "cve_identity"

    def test_cve_passes_when_id_in_evidence(self):
        ctx = _ctx(
            "The intrusion exploited CVE-2024-12345 as the root cause.",
            supporting_evidence="scanner hit: CVE-2024-12345 in httpd banner",
        )
        assert ekg.check(ctx) is None


class TestParametricAndNegatives:
    def test_parametric_admission_refused(self):
        ctx = _ctx("Vendor is AcmeCorp from my training knowledge.")
        fail = ekg.check(ctx)
        assert fail is not None
        assert fail.get("detail_gate") == "parametric_source"

    def test_suspected_not_gated(self):
        ctx = _ctx(
            "MAC prefix B8:27:EB belongs to ExampleNet based on the OUI.",
            tier="SUSPECTED",
        )
        assert ekg.check(ctx) is None

    def test_plain_observation_ok(self):
        ctx = _ctx(
            "DHCPDISCOVER for MAC b8:27:eb:00:00:01 at 2031-02-04T12:00:00+01:00.",
            cmds=[("strings dhcp.log",
                   "DHCPDISCOVER from b8:27:eb:00:00:01")],
        )
        assert ekg.check(ctx) is None


@pytest.mark.skipif(not _OUI_AVAILABLE, reason=_OUI_SKIP_REASON)
class TestOuiLookupTool:
    def test_raspberry_pi_prefix(self):
        from tools.enrichment import oui_lookup
        r = oui_lookup("b8:27:eb:00:00:01")
        assert r["success"] is True
        assert r["found"] is True
        assert "RASPBERRY PI" in (r.get("organization") or "").upper()


class TestMalwareFamilyAttribution:
    """A family or tool name bound to a malware-class noun is the analyst's
    unless a cited tool printed it. Grammar only: no list of families."""

    def test_a_name_no_tool_printed_is_refused(self):
        out = ekg.check(_ctx(
            "A RedCurtain implant on the workstation beacons to 198.51.100.7 over 443",
            tier="LIKELY",
            cmds=[("<py>:vol_netscan", "svc_update.exe 4412 TCPv4 10.0.0.5:49812 198.51.100.7:443")]))
        assert out is not None
        assert out["detail_gate"] == "malware_family_attribution"
        assert out["unverified_name"] == "RedCurtain"

    def test_the_name_a_scanner_printed_passes(self):
        out = ekg.check(_ctx(
            "The beacon is Cobalt Strike, staged through svc_update.exe",
            tier="LIKELY",
            cmds=[("<py>:yara_scan_file", "rule CobaltStrike_Beacon matched: Cobalt Strike stager")]))
        assert out is None

    def test_a_sentence_opener_is_not_a_family_name(self):
        out = ekg.check(_ctx(
            "The implant persisted through a service; the Windows beacon ran at boot",
            tier="LIKELY", cmds=[("<py>:vol_svcscan", "svc_update running")]))
        assert out is None

    def test_a_hypothesis_tier_is_left_to_the_citation_readers(self):
        out = ekg.check(_ctx(
            "A RedCurtain implant on the workstation beacons to 198.51.100.7",
            tier="SUSPECTED", cmds=[("<py>:vol_netscan", "svc_update.exe 4412")]))
        assert out is None

    def test_the_analysts_own_supporting_evidence_does_not_verify_the_name(self):
        """Repeating the family name in supporting_evidence is the claim said
        twice; only a cited tool printing it counts."""
        out = ekg.check(_ctx(
            "svc_update.exe (pid 4412) is a Cobalt Strike beacon to 203.0.113.9:443",
            tier="LIKELY",
            supporting_evidence="netscan: svc_update.exe 4412 -> 203.0.113.9:443, consistent "
                                "with a Cobalt Strike beacon",
            cmds=[("<py>:vol_netscan", "svc_update.exe 4412 TCPv4 10.0.0.5:49812 203.0.113.9:443")]))
        assert out is not None and out["unverified_name"] == "Cobalt Strike"
