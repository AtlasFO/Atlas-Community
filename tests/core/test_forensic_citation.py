"""Citations a human can read — and the refusal to invent structure.

Positional field-mapping would publish `fls` output as "Timestamp:" and
"Machine:" and paste hexdumps in as evidence; the fixtures have that shape.
"""
from __future__ import annotations

from core import forensic_citation as fc

FLS_ROW = ("d/d 1234-128-1:\tDocuments and Settings\n"
           "d/d 5678-144-6:\tProgramData")
HEXDUMP = ("00000000  de ad be ef 00 01 02 03  04 05 06 07 08 09 0a 0b  "
           "|................|\n"
           "00000010  0c 0d 0e 0f 10 11 12 13  14 15 16 17 18 19 1a 1b  "
           "|................|")


class TestFieldValidation:
    """The single rule: a label is earned, never assumed from position."""

    def test_fls_output_is_never_called_a_timestamp(self):
        assert fc.normalize_timestamp("d/d 1234-128-1:") == ""

    def test_a_real_timestamp_normalizes(self):
        assert fc.normalize_timestamp(
            "2031-02-04 12:00:00.123456700 (UTC)") == "2031-02-04 12:00:00 UTC"
        assert fc.normalize_timestamp(
            "2031-02-05T12:05:00Z") == "2031-02-05 12:05:00 UTC"

    def test_a_directory_name_is_never_called_a_host(self):
        assert not fc.looks_like_host("Documents and Settings")
        assert not fc.looks_like_host("ProgramData/")

    def test_a_known_case_host_is_accepted(self):
        assert fc.looks_like_host("FILESRV01", ["FILESRV01"])

    def test_artifact_names_come_back_from_working_paths(self):
        assert fc.artifact_display_name(
            "analysis/FILESRV01_Security_evtx.csv") == "Security.evtx"
        assert fc.artifact_kind("Security.evtx") == "Windows Event Log"
        assert fc.artifact_kind("analysis/h1_mft.csv") == "NTFS Master File Table"
        assert fc.artifact_kind("evidence/fw/2031-02-03.log") == "Firewall Log"


class TestBinaryNoise:
    def test_a_hexdump_is_not_quotable(self):
        assert fc.is_binary_noise(HEXDUMP)

    def test_ordinary_text_is_quotable(self):
        assert not fc.is_binary_noise("An account was successfully logged on.")

    def test_opaque_content_is_summarized_not_pasted(self):
        out = fc.summarize_opaque(HEXDUMP)
        assert "not reproduced" in out
        assert "de ad be" not in out


class TestCitationRendering:
    def test_a_full_event_reads_like_a_reference(self):
        cite = fc.citation_from_event({
            "text": "An account was successfully logged on. Account: tempadmin",
            "record_ref": "analysis/FILESRV01_Security_evtx.csv:1200:4624",
            "timestamp": "2031-02-04T12:00:00Z",
            "host": "FILESRV01", "call_id": 77,
        }, known_hosts=["FILESRV01"])
        rendered = cite.render()
        assert "FILESRV01" in rendered
        assert "Windows Event Log Security.evtx" in rendered
        assert "Event 4624 (successful logon)" in rendered
        assert "2031-02-04 12:00:00 UTC" in rendered

    def test_unidentifiable_output_degrades_to_a_quote(self):
        """No fake labels, just what was actually seen."""
        cite = fc.citation_from_event(
            {"text": FLS_ROW, "source": "evidence_index", "line": 1,
             "call_id": 21})
        rendered = cite.render()
        assert "Timestamp" not in rendered
        assert "Machine" not in rendered
        assert cite.timestamp == ""
        assert "Documents and Settings" in rendered  # shown honestly, as a quote

    def test_a_hexdump_event_is_summarized(self):
        cite = fc.citation_from_event({"text": HEXDUMP, "call_id": 41})
        assert "not reproduced" in cite.render()
        assert "de ad" not in cite.render()

    def test_correlated_provenance_is_marked(self):
        cite = fc.citation_from_event(
            {"text": "something", "provenance": "correlated"})
        assert "correlated" in cite.render()

    def test_an_empty_event_says_so_rather_than_guessing(self):
        assert "source not identified" in fc.citation_from_event({}).render()


class TestRenderCitations:
    def test_duplicates_collapse_and_the_rest_are_counted(self):
        events = [{"text": "same", "source": "a.log", "call_id": 1}] * 3
        events += [{"text": f"row {i}", "source": "a.log", "call_id": i}
                   for i in range(20)]
        out = fc.render_citations(events, limit=5)
        assert out.count("\n- ") <= 6
        assert "further record(s)" in out

    def test_no_events_renders_nothing(self):
        assert fc.render_citations([]) == ""

    def test_call_ids_stay_available_for_tracing(self):
        out = fc.render_citations([{"text": "x", "source": "a.log",
                                    "call_id": 9}])
        assert "call_id=9" in out


class TestRecordHost:
    """The host of a record is the record's, in one rule for the bullets
    and the timeline: its source path's host first, then a host-shaped
    host field, then the one case host its text names."""

    def test_the_source_paths_host_wins_in_either_host_order(self):
        ev = {"text": "An account was successfully logged on from CORP-WS01. Account: jane.doe",
              "record_ref": "analysis/corp-fs01-security.csv:12:4624", "host": ""}
        for hosts in (["CORP-WS01", "CORP-FS01"], ["CORP-FS01", "CORP-WS01"]):
            assert fc.record_host(ev, hosts) == "CORP-FS01"
            assert fc.citation_from_event(ev, known_hosts=hosts).host == "CORP-FS01"

    def test_a_text_naming_two_hosts_decides_nothing_and_the_claim_stands_in(self):
        ev = {"text": "CORP-WS01 reached CORP-FS01 over SMB", "source": "evidence_index call_id=12"}
        hosts = ["CORP-WS01", "CORP-FS01"]
        assert fc.record_host(ev, hosts) == ""
        assert fc.citation_from_event(ev, known_hosts=hosts, claim_host="CORP-DC01").host == "CORP-DC01"
        one = {"text": "jane.doe logged on at CORP-FS01", "source": "evidence_index call_id=12"}
        assert fc.record_host(one, hosts) == "CORP-FS01"

    def test_a_host_shaped_host_field_counts_a_digits_cell_does_not(self):
        hosts = ["CORP-WS01"]
        assert fc.record_host({"text": "x", "host": "CORP-WS01", "source": "evidence_index call_id=3"}, hosts) == "CORP-WS01"
        assert fc.record_host({"text": "x", "host": "17", "source": "evidence_index call_id=3"}, hosts) == ""


def test_an_image_not_named_after_its_host_resolves_through_the_evidence_links(tmp_path):
    import json
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence" / "disk").mkdir(parents=True)
    (case / "evidence" / "disk" / "img-0001.raw").write_bytes(b"\0" * 512)
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": "evidence/disk/img-0001.raw"}]}), encoding="utf-8")
    ev = {"text": "An account was successfully logged on. Account: jane.doe",
          "record_ref": "evidence/disk/img-0001.raw::Windows/System32/winevt/Logs/Security.evtx:12:4624"}
    assert fc.record_host(ev, ["CORP-WS01", "CORP-FS01"], case) == "CORP-WS01"
    assert fc.record_host(ev, ["CORP-WS01", "CORP-FS01"]) == ""           # without the root: no label in the path
    assert fc.citation_from_event(ev, known_hosts=["CORP-WS01"], case_dir=case).host == "CORP-WS01"
    from core.evidence_resolver import format_evidence_markdown
    pack = {"events": [dict(ev, timestamp="2031-03-10T12:00:00Z", call_id=7)]}
    assert "CORP-WS01" in format_evidence_markdown(pack, compact=True, known_hosts=["CORP-WS01", "CORP-FS01"],
                                                   case_dir=case)
