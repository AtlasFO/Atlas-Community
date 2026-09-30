"""The path citation extractor must not swallow trailing prose or the
sentence's own punctuation."""
from __future__ import annotations

from tools._gates._citation import deterministic_cite_check, extract_claims


def test_win_path_stops_before_and():
    finding = (
        "jane.doe created D:\\Share\\report_01.txt and "
        "D:\\Archive\\report_01.txt around 2031-02-04"
    )
    claims = [v for k, v in extract_claims(finding) if k == "path"]
    assert "D:\\Share\\report_01.txt" in claims
    assert "D:\\Archive\\report_01.txt" in claims
    assert not any(" and " in c for c in claims)


def test_cite_check_passes_with_both_paths_in_evidence():
    finding = (
        "jane.doe created D:\\Share\\report_01.txt and "
        "D:\\Archive\\report_01.txt"
    )
    evidence = (
        "EDR FileCreated path=D:\\Share\\report_01.txt; "
        "path=D:\\Archive\\report_01.txt; IP 10.0.0.5"
    )
    # Also need the IP if extracted
    finding_full = finding + " from 10.0.0.5"
    result = deterministic_cite_check(finding_full, evidence)
    assert result["verdict"] == "ALL_CITED", result


def test_a_path_that_ends_a_sentence_is_cited_without_its_full_stop():
    finding = ("The access key appears in the clear in Users/jane.doe/Downloads/keys.csv. "
               "The Desktop holds the planning documents.")
    evidence = "keys.csv (call 56, path mnt/CASE-A/fs/Users/jane.doe/Downloads/keys.csv): AccessKeyId=EXAMPLE"
    claims = [v for k, v in extract_claims(finding) if k == "path"]
    assert claims == ["/jane.doe/Downloads/keys.csv"]
    assert deterministic_cite_check(finding, evidence)["verdict"] == "ALL_CITED"


def test_trailing_dots_and_an_ellipsis_leave_a_windows_path_whole():
    claims = [v for k, v in extract_claims(
        "It was written to C:\\Users\\a\\b.txt. Then C:\\Temp\\c.dat... followed.") if k == "path"]
    assert claims == ["C:\\Users\\a\\b.txt", "C:\\Temp\\c.dat"]


def test_dots_inside_a_path_stay():
    claims = [v for k, v in extract_claims("The script /etc/rc.d/init.d/net ran.") if k == "path"]
    assert claims == ["/etc/rc.d/init.d/net"]
