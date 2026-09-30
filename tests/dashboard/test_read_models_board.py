"""The Case Findings projection: hosts a belief names, versions of one
belief, what needs attention, and the counts the band shows."""
from __future__ import annotations

import json

from dashboard import read_models


def _write(tmp_path, nodes, *, case_md=""):
    atlas = tmp_path / ".atlas"
    atlas.mkdir(parents=True, exist_ok=True)
    (atlas / "claim_graph.json").write_text(json.dumps({"nodes": nodes, "edges": []}))
    (tmp_path / "CASE.md").write_text(case_md)
    read_models._board_cache.clear()
    return str(tmp_path)


def _claim(i, statement, *, confidence="SUSPECTED", host="", status="new", **extra):
    node = {"id": f"C{i:04d}", "kind": "claim", "statement": statement,
            "confidence": confidence, "host": host, "status": status,
            "evidence": [{"call_id": 10 + i, "artifact": "x"}],
            "created_at": f"2026-01-01T00:{i:02d}:00Z"}
    node.update(extra)
    return node


class TestHosts:
    def test_explicit_host_wins(self, tmp_path):
        case = _write(tmp_path, {"C0001": _claim(1, "something", host="srv-a")})
        assert read_models.evidence_board(case)["board"]["C0001"]["host"] == "srv-a"

    def test_host_read_from_the_statement_against_the_case_brief(self, tmp_path, monkeypatch):
        import core.forensic_citation as fc
        monkeypatch.setattr(fc, "known_case_hosts", lambda _cd: ["srv-a", "srv-b"])
        case = _write(tmp_path, {
            "C0001": _claim(1, "A service was installed on srv-a at 10:00"),
            "C0002": _claim(2, "Lateral movement from srv-a to srv-b via RDP"),
            "C0003": _claim(3, "No host named here"),
        })
        board = read_models.evidence_board(case)["board"]
        assert board["C0001"]["host"] == "srv-a"
        # naming two hosts is an estate belief: listed, but no single lane
        assert board["C0002"]["host"] == ""
        assert board["C0002"]["hosts"] == ["srv-a", "srv-b"]
        assert board["C0003"]["hosts"] == []


class TestVersionChains:
    def test_same_statement_recorded_again_is_a_newer_version(self, tmp_path):
        case = _write(tmp_path, {
            "C0001": _claim(1, "Account x created on host y at 2026-01-01T09:00:00Z", confidence="LIKELY"),
            "C0009": _claim(9, "Account x created on host y at 2026-01-01T09:00:00Z", confidence="CONFIRMED"),
        })
        d = read_models.evidence_board(case)
        old, new = d["board"]["C0001"], d["board"]["C0009"]
        assert old["version"]["current"] is False and old["gone"] is True
        assert new["version"]["current"] is True and new["version"]["of"] == 2
        assert old["version"]["superseded_by"] == "C0009"
        assert d["counts"]["chains"] == 1
        assert d["counts"]["active"] == 1 and d["counts"]["gone"] == 1

    def test_restated_belief_chains(self, tmp_path):
        # The newer statement carries the older one's content words: a
        # restatement, as the recorder would also judge it.
        case = _write(tmp_path, {
            "C0001": _claim(1, "Local account tempadmin (SID S-1-5-21-1111111111-2222222222-3333333333-1001) created on host-a at 2026-01-01T09:00:00Z", confidence="LIKELY"),
            "C0009": _claim(9, "Local account tempadmin (SID S-1-5-21-1111111111-2222222222-3333333333-1001) created on host-a at 2026-01-01T09:00:00Z by user jdoe", confidence="CONFIRMED"),
        })
        assert read_models.evidence_board(case)["board"]["C0009"]["version"]["of"] == 2

    def test_shared_identifiers_alone_do_not_chain(self, tmp_path):
        # Two different beliefs about one account share its SID and a time;
        # they are not versions of each other.
        case = _write(tmp_path, {
            "C0001": _claim(1, "Local account tempadmin (SID S-1-5-21-1111111111-2222222222-3333333333-1001) created on host-a at 2026-01-01T09:00:00Z", confidence="CONFIRMED"),
            "C0009": _claim(9, "Principal disposition: SID S-1-5-21-1111111111-2222222222-3333333333-1001 authenticated to the domain controller via Kerberos from 10.0.0.9 at 2026-01-01T09:00:00Z, consistent with credential reuse", confidence="UNCONFIRMED"),
        })
        d = read_models.evidence_board(case)
        assert d["board"]["C0001"]["version"] is None and d["board"]["C0001"]["gone"] is False

    def test_observations_are_never_versioned(self, tmp_path):
        obs = {"kind": "observation", "statement": "Logon from 10.0.0.5 at 2026-01-01T09:00:00Z",
               "confidence": "CONFIRMED", "status": "new", "evidence": []}
        case = _write(tmp_path, {"O0001": {"id": "O0001", **obs}, "O0002": {"id": "O0002", **obs}})
        d = read_models.evidence_board(case)
        assert all(b["version"] is None for b in d["board"].values())
        assert d["counts"]["kind"] == {"observation": 2}


class TestAttentionAndCounts:
    def test_attention_flags_and_counts(self, tmp_path):
        case = _write(tmp_path, {
            "C0001": _claim(1, "a", confidence="CONFIRMED"),
            "C0002": _claim(2, "b", status="needs_review"),
            "X0001": {"id": "X0001", "kind": "conflict", "status": "conflict", "statement": "a vs b",
                      "conflicting_claim_ids": ["C0001", "C0002"], "evidence": []},
            "R0001": {"id": "R0001", "kind": "recommendation", "statement": "isolate", "status": "new",
                      "confidence": "LIKELY", "evidence": []},
        })
        d = read_models.evidence_board(case)
        assert d["board"]["C0001"]["attention"] is False
        assert d["board"]["C0002"]["attention"] is True
        assert d["board"]["X0001"]["attention"] is True
        assert d["counts"]["kind"] == {"claim": 2, "conflict": 1, "recommendation": 1}
        assert d["counts"]["confidence"]["claim"] == {"CONFIRMED": 1, "SUSPECTED": 1}
        assert d["counts"]["conflicts"] == 1 and d["counts"]["needs_review"] == 1
        assert d["counts"]["evidence_refs"] == 2

    def test_missing_graph_answers_without_raising(self, tmp_path):
        read_models._board_cache.clear()
        assert read_models.evidence_board(str(tmp_path))["graph"] is None
