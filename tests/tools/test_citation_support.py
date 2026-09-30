"""One judgement of whether a finding's citation supports it, shared by the
record-time advisory, the report gate and the duplicate guard. A positive
claim needs a cited output showing one of its identifiers; an absence claim
needs a cited complete search of what it says is missing; an absence claim
with no search behind it is unsupported."""
from __future__ import annotations

from tools._gates import citation_support as cs


def _call(cid, cmd, excerpt="", **extra):
    e = {"type": "tool_call", "call_id": cid, "cmd": cmd, "success": True,
         "truncated": False, "stdout_excerpt": excerpt}
    e.update(extra)
    return e


# A complete query over the exported Security logon rows of the window: the
# analyst saw every matching row, and the one logon shown came from the
# attacker's address.
SECURITY_QUERY = _call(
    206, "<py>:table_table_query",
    '{"success": true, "path": "analysis/dc_security_4624_4625.csv", '
    '"matched_rows": 11, "returned_rows": 11, "rows": [{"TimeCreated": '
    '"2020-09-19 03:21:48", "EventId": "4624", "LogonType": "10", '
    '"RemoteHost": "203.0.113.9", "SubjectUserName": "Administrator"}]}')
TRUNCATED_GREP = _call(
    214, "sudo ngrep -q -I evidence/network/capture.pcap -i POST tcp",
    "T 10.20.30.115:49694 -> 203.0.113.9:443 [AP] POST /upload", truncated=True)
MEMORY_INFO = _call(77, "vol -f evidence/host.mem windows.info",
                    '[{"Variable": "Kernel Base", "Value": "0xf80162a14000"}]')
OWN_WORDS = {"type": "finding", "call_id": 64, "description": "an earlier finding",
             "stdout_excerpt": ""}

ABSENCE = ("No second principal or backdoor account was identified: the Security "
           "4720 account-creation events in the attack window show no new account")
POSITIVE = "The attacker at 203.0.113.9 posted data over port 443"


class TestAbsenceClaims:
    def test_a_complete_search_of_the_claims_sources_supports_it(self):
        assert cs.citation_supports(ABSENCE, [SECURITY_QUERY],
                                    tool_calls=[SECURITY_QUERY]) is True

    def test_the_absent_identifier_is_not_demanded_in_the_output(self):
        stmt = "No logon by account backdoor_adm was recorded in the Security log"
        assert cs.citation_supports(stmt, [SECURITY_QUERY],
                                    tool_calls=[SECURITY_QUERY]) is True

    def test_a_truncated_search_does_not_ground_an_absence(self):
        stmt = "No POST requests to any external address were observed in the capture"
        assert cs.citation_supports(stmt, [TRUNCATED_GREP],
                                    tool_calls=[TRUNCATED_GREP]) is False

    def test_an_absence_resting_on_the_runs_own_words_is_unsupported(self):
        assert cs.citation_supports(ABSENCE, [OWN_WORDS], tool_calls=[SECURITY_QUERY]) is False

    def test_an_uncited_finding_is_not_judged_here(self):
        """Nothing cited is lineage_required's refusal at record time; the
        report gate has nothing to read and does not flag it."""
        assert cs.citation_supports(ABSENCE, [], tool_calls=[SECURITY_QUERY]) is None

    def test_an_absence_citing_a_search_with_no_recorded_output_cannot_be_judged(self):
        """The contract every reader keeps: a cited search that left nothing
        behind to read is neither support nor its absence."""
        silent = _call(9, "tcpdump -r evidence/capture.pcap -nn tcp port 80")
        assert cs.citation_supports(ABSENCE, [silent], tool_calls=[silent]) is None

    def test_a_categorised_absence_needs_the_search_of_its_category(self):
        """A "no logon" claim is grounded by a Security-log search, not by
        any complete call that happens to be cited."""
        stmt = "No logon events for the created accounts were found in the incident window"
        assert cs.citation_supports(stmt, [MEMORY_INFO], tool_calls=[MEMORY_INFO]) is False
        assert cs.citation_supports(stmt, [SECURITY_QUERY, MEMORY_INFO],
                                    tool_calls=[SECURITY_QUERY, MEMORY_INFO]) is True

    def test_a_cut_view_the_tool_returned_whole_is_still_not_a_complete_search(self):
        cut = {**SECURITY_QUERY, "view_truncated": True, "view_omitted_chars": 900}
        stmt = "No account was created during the window per the Security log"
        assert cs.citation_supports(stmt, [cut], tool_calls=[cut]) is False


class TestPositiveClaimsAreJudgedAsBefore:
    def test_shown_identifier_supports(self):
        assert cs.citation_supports(POSITIVE, [TRUNCATED_GREP], tool_calls=[TRUNCATED_GREP]) is True

    def test_missing_identifier_does_not(self):
        assert cs.citation_supports(POSITIVE, [MEMORY_INFO], tool_calls=[MEMORY_INFO]) is False

    def test_no_output_cannot_be_judged(self):
        silent = _call(5, "strings -a evidence/x.bin")
        assert cs.citation_supports(POSITIVE, [silent], tool_calls=[silent]) is None

    def test_a_claim_naming_nothing_checkable_is_not_refused(self):
        assert cs.citation_supports("the archive could not be opened", [MEMORY_INFO],
                                    tool_calls=[MEMORY_INFO]) is True

    def test_a_plain_word_after_a_cue_cannot_refuse_a_citation(self):
        assert cs.citation_supports("the process migration was observed", [MEMORY_INFO],
                                    tool_calls=[MEMORY_INFO]) is True


class TestSuggestions:
    def test_an_absence_claim_is_pointed_at_complete_searches_before_anything_showing_its_address(self):
        """The truncated packet grep prints the address and is newest; it is
        left out, since citing it walks the analyst into the truncation
        refusal, and the complete Security search comes first."""
        calls = [MEMORY_INFO, SECURITY_QUERY, TRUNCATED_GREP]
        stmt = ("No second principal was identified: no logon by any created account "
                "in the window, and all activity traces to the attacker at 203.0.113.9")
        out = cs.calls_showing(stmt, calls, complete_only=True)
        assert [o["call_id"] for o in out] == [206]
        assert "searched" in out[0]["why"]

    def test_a_positive_claim_is_pointed_at_the_call_showing_its_identifier(self):
        out = cs.calls_showing(POSITIVE, [MEMORY_INFO, SECURITY_QUERY, TRUNCATED_GREP])
        assert [o["call_id"] for o in out] == [214, 206]   # newest first
        assert all("203.0.113.9" in o["why"] for o in out)


class TestOutsideLookups:
    """A lookup echoes the value it was asked about: it grounds what a
    provider says (the external-knowledge gate's question) and never shows
    that the value was present in the case."""

    LOOKUP = _call(301, "<py>:enrich_vt_lookup_ip",
                   '{"ip": "203.0.113.9", "malicious": 12, "as_owner": "Example Net"}')

    def test_a_presence_claim_citing_only_a_lookup_is_unsupported(self):
        assert cs.citation_supports(POSITIVE, [self.LOOKUP], tool_calls=[self.LOOKUP]) is False
        stmt = "The hash, rated malicious by the provider, deleted the shadow copies on 203.0.113.9"
        assert cs.citation_supports(stmt, [self.LOOKUP], tool_calls=[self.LOOKUP]) is False

    def test_the_evidence_call_supports_it_with_or_without_the_lookup(self):
        calls = [SECURITY_QUERY, self.LOOKUP]
        assert cs.citation_supports(POSITIVE, calls, tool_calls=calls) is True
        assert cs.citation_supports(POSITIVE, [SECURITY_QUERY], tool_calls=calls) is True

    def test_repair_suggestions_never_offer_a_lookup(self):
        shown = cs.calls_showing(POSITIVE, [SECURITY_QUERY, self.LOOKUP])
        assert [c["call_id"] for c in shown] == [206]
