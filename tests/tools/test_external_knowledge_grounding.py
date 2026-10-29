"""Tests for generalized external_knowledge_grounding + enrich.oui_lookup."""
import json
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
        """Grounded by a cited call's output; the same text only in
        supporting_evidence, the analyst's own words, is not."""
        out = '{"organization":"Raspberry Pi Foundation","registry":"IEEE MA-L","prefix_dashed":"B8-27-EB"}'
        assert ekg.check(_ctx('MAC prefix B8:27:EB belongs to Raspberry Pi Foundation per IEEE OUI.', cmds=[('<py>:enrich_oui_lookup', out)])) is None
        assert ekg.check(_ctx('MAC prefix B8:27:EB belongs to Raspberry Pi Foundation per IEEE OUI.', supporting_evidence='enrich_oui_lookup' + ' ' + out)) is not None


class TestTheVerifyingToolIsTheCallsOwnRecord:
    def test_the_cited_lookup_s_name_grounds_it_without_the_marker_fields(self):
        """The output names no registry field; that the cited call ran the
        OUI lookup is the trace's record of the call, not the analyst's words."""
        desc = "MAC prefix B8:27:EB belongs to Raspberry Pi Foundation per IEEE OUI."
        assert ekg.check(_ctx(desc, cmds=[("<py>:enrich_oui_lookup", '{"organization": "Raspberry Pi Foundation"}')])) is None

    def test_a_refusal_names_the_suspected_route(self):
        out = ekg.check(_ctx("The SHA256 hash abcdef0123456789abcdef0123456789abcdef0123456789"
                             "abcdef0123456789 is known malware identified as Emotet.",
                             supporting_evidence="vt_lookup_hash: Emotet"))
        assert out is not None and out.get("detail_gate") == "hash_malware_family"
        assert "SUSPECTED" in out["error"]


class TestOtherExternalClasses:
    def test_ip_geo_refused(self):
        ctx = _ctx("IP 8.8.8.8 is located in the United States (ASN 15169).")
        fail = ekg.check(ctx)
        assert fail is not None
        assert fail.get("detail_gate") == "ip_geo_asn_reputation"

    def test_ip_geo_passes_with_vt(self):
        """Grounded by a cited call's output; the same text only in
        supporting_evidence, the analyst's own words, is not."""
        out = '{"country":"US","asn":15169}'
        assert ekg.check(_ctx('IP 8.8.8.8 is located in the United States.', cmds=[('<py>:enrich_vt_lookup_ip', out)])) is None
        assert ekg.check(_ctx('IP 8.8.8.8 is located in the United States.', supporting_evidence='enrich_vt_lookup_ip' + ' ' + out)) is not None

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
            "The intrusion exploited CVE-2031-12345 as the root cause."
        )
        fail = ekg.check(ctx)
        assert fail is not None
        assert fail.get("detail_gate") == "cve_identity"

    def test_cve_passes_when_id_in_evidence(self):
        """Grounded by a cited call's output; the same text only in
        supporting_evidence, the analyst's own words, is not."""
        out = 'scanner hit: CVE-2031-12345 in httpd banner'
        assert ekg.check(_ctx('The intrusion exploited CVE-2031-12345 as the root cause.', cmds=[('<py>:yara_scan_file', out)])) is None
        assert ekg.check(_ctx('The intrusion exploited CVE-2031-12345 as the root cause.', supporting_evidence='yara_scan_file' + ' ' + out)) is not None


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


class TestLookupFirst:
    """ATLAS_EXTERNAL_LOOKUP_FIRST: protocol words are plain words, a name
    is grounded only by printed output (a cited lookup counts, a rule the
    analyst wrote never does), and the refusal leads with a ready check."""

    @staticmethod
    def _yara(matches, args='{"file_path": "/case/export/svc_update.exe"}'):
        import json
        return {"type": "tool_call", "cmd": "<py>:yara_yara_scan_file", "success": True, "args": args,
                "stdout_excerpt": json.dumps({"success": True, "file": "/case/export/svc_update.exe",
                                              "match_count": len(matches), "matches": matches})}

    @staticmethod
    def _with(ctx, entries):
        ctx.idx.by_call_id.update(entries)
        ctx.input_call_ids = list(ctx.input_call_ids) + list(entries)
        return ctx

    def test_a_protocol_word_binds_the_name_before_it(self):
        out = ekg.check(_ctx("The RedCurtain SMB beacon contacted 198.51.100.7.", tier="LIKELY",
                             cmds=[("<py>:vol_netscan", "redcurtain.exe 4412 198.51.100.7:445")]))
        assert out is None   # "RedCurtain" is printed; "SMB" is not part of the name

    def test_a_capture_of_protocol_words_is_no_name(self):
        assert ekg.check(_ctx("An SMB beacon ran from the PowerShell loader.", tier="LIKELY",
                              cmds=[("<py>:vol_netscan", "x")])) is None

    def test_switch_off_keeps_the_protocol_word_in_the_name(self, monkeypatch):
        monkeypatch.setenv("ATLAS_EXTERNAL_LOOKUP_FIRST", "0")
        out = ekg.check(_ctx("The RedCurtain SMB beacon contacted 198.51.100.7.", tier="LIKELY",
                             cmds=[("<py>:vol_netscan", "redcurtain.exe 4412 198.51.100.7:445")]))
        assert out is not None and out["unverified_name"] == "RedCurtain SMB"

    def test_a_cited_lookup_grounds_the_name(self):
        ctx = _ctx("svc_update.exe is a RedCurtain loader.", tier="LIKELY",
                   cmds=[("<py>:enrich_vt_lookup_hash",
                          '{"popular_threat_label": "trojan.redcurtain/loader", "malicious": 41}')])
        assert ekg.check(ctx) is None

    def test_the_command_line_never_grounds_the_name(self):
        ctx = _ctx("svc_update.exe is a RedCurtain loader.", tier="LIKELY",
                   cmds=[("<py>:strings_strings_grep", "")])
        ctx.idx.by_call_id[1]["args"] = '{"pattern": "RedCurtain"}'
        out = ekg.check(ctx)
        assert out is not None and out["unverified_name"] == "RedCurtain"

    def test_a_shipped_rule_match_grounds_and_no_match_grounds_nothing(self):
        hit = self._yara([{"rule": "RedCurtain_Loader", "namespace": "apt.yar", "tags": [], "meta": {}}])
        miss = self._yara([])
        desc = "svc_update.exe is a RedCurtain loader."
        assert ekg.check(self._with(_ctx(desc, tier="LIKELY"), {7: hit})) is None
        out = ekg.check(self._with(_ctx(desc, tier="LIKELY"), {7: miss}))
        assert out is not None and out["unverified_name"] == "RedCurtain"

    def test_an_analyst_authored_rule_never_grounds(self, tmp_path):
        hit = [{"rule": "RedCurtain", "namespace": "default", "tags": [], "meta": {}}]
        desc = "svc_update.exe is a RedCurtain loader."
        inline = self._yara(hit, args='{"file_path": "/case/x.exe", "inline_rule": "rule RedCurtain {condition: true}"}')
        assert ekg.check(self._with(_ctx(desc, tier="LIKELY"), {7: inline})) is not None
        rules = tmp_path / "analysis" / "mine.yar"
        under_case = self._yara(hit, args='{"file_path": "/case/x.exe", "rules_path": "%s"}' % rules)
        ctx = self._with(_ctx(desc, tier="LIKELY"), {7: under_case})
        ctx.log.case_dir = lambda: str(tmp_path)
        assert ekg.check(ctx) is not None
        strings = {**self._yara(hit), "cmd": "<py>:yara_yara_scan_strings"}
        assert ekg.check(self._with(_ctx(desc, tier="LIKELY"), {7: strings})) is not None

    def test_a_rule_written_outside_the_case_during_the_run_never_grounds(self, tmp_path):
        """A rules file the analyst wrote to /tmp through a shell or a script
        is the analyst's word; one older than the run's first call is not."""
        hit = [{"rule": "RedCurtain", "namespace": "default", "tags": [], "meta": {}}]
        desc = "svc_update.exe is a RedCurtain loader."
        rules = tmp_path / "tmp" / "x.yar"
        rules.parent.mkdir()
        rules.write_text("rule RedCurtain { condition: true }")
        scan = self._yara(hit, args=json.dumps({"file_path": "/case/x.exe", "rules_path": str(rules)}))

        def run(first_ts):
            ctx = self._with(_ctx(desc, tier="LIKELY"), {7: scan})
            ctx.log._entries = [{"type": "trace_opened", "ts": first_ts}]
            return ekg.check(ctx)
        assert run("2001-01-01T00:00:00+00:00") is not None     # written after the run began
        assert run("2031-01-01T00:00:00+00:00") is None         # present before the run began

    def test_the_refusal_leads_with_a_ready_call_built_from_the_cited_call(self):
        read = {"type": "tool_call", "cmd": "<py>:tsk_tsk_icat", "success": True,
                "args": '{"file_path": "/case/export/svc_update.exe"}', "stdout_excerpt": "wrote 81920 bytes"}
        desc = ("svc_update.exe (sha256 " + "ab" * 32 + ") is a RedCurtain loader.")
        out = ekg.check(self._with(_ctx(desc, tier="LIKELY"), {7: read}))
        assert out["ready_call"] == {"tool": "yara.scan_file",
                                     "args": {"file_path": "/case/export/svc_update.exe"}}
        err = out["error"]
        assert err.index("Check it: yara.scan_file") < err.index("SUSPECTED hypothesis")
        assert "enrich.vt_lookup_hash('" + "ab" * 32 + "')" in err
        assert "not by a rule you write" in err
