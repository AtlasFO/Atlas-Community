"""Regression tests for the committed ATT&CK technique table data.

These run against the real committed `share/.common/mitre_techniques.json`
(the install seed), not a synthetic fixture: a table built from a bundle in
which ATT&CK v19 revoked T1562.001, by a build that drops revoked entries,
makes the evidence_strength gate refuse that ID. Every ID here is either a
revoked ID analysts still cite or a staple the analyst must be able to tag;
if a rebuild loses one, this fails before a training run does.
"""
import json
import os

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TABLE_PATH = os.path.join(REPO_ROOT, "share", ".common", "mitre_techniques.json")

# Common (sub-)techniques a ransomware/intrusion case needs to tag. Includes
# both live v19 IDs and historical IDs that v19 revoked but analysts still
# cite (T1562.001 → T1685, T1070.001 → T1685.005).
SAMPLE_TIDS = [
    "T1562.001",  # Impair Defenses: Disable or Modify Tools (revoked → T1685)
    "T1566.001",  # Phishing: Spearphishing Attachment
    "T1204.002",  # User Execution: Malicious File
    "T1070.001",  # Indicator Removal: Clear Windows Event Logs (revoked → T1685.005)
    "T1021.002",  # Remote Services: SMB/Windows Admin Shares
    "T1486",      # Data Encrypted for Impact
    # v19 successors must be live so superseded_by points somewhere real.
    "T1685",
    "T1685.005",
]


@pytest.fixture(scope="module")
def table():
    assert os.path.exists(TABLE_PATH), f"committed table missing: {TABLE_PATH}"
    with open(TABLE_PATH) as f:
        return json.load(f)


class TestCommittedTechniqueTable:
    @pytest.mark.parametrize("tid", SAMPLE_TIDS)
    def test_sample_id_validates(self, tid, table):
        from tools.mitre import validate
        r = validate(tid, path=TABLE_PATH)
        assert r["exists"], (
            f"{tid} missing from {TABLE_PATH} — did a cache rebuild drop "
            "revoked/renamed techniques again? See build_mitre_cache.py."
        )
        assert r["name"]

    def test_revoked_ids_carry_successor(self, table):
        from tools.mitre import validate
        for old, new in [("T1562.001", "T1685"), ("T1070.001", "T1685.005")]:
            r = validate(old, path=TABLE_PATH)
            assert r.get("status") == "revoked"
            assert r.get("superseded_by") == new
            # ... and the successor must itself be a live entry.
            succ = table["techniques"][new]
            assert not succ.get("status")

    def test_retired_entries_have_no_keywords(self, table):
        """Retired IDs are validation-only: keywords stay empty so mitre_map
        never ranks a superseded ID above its live successor."""
        offenders = [
            tid for tid, info in table["techniques"].items()
            if info.get("status") and info.get("keywords")
        ]
        assert not offenders, f"retired entries with keywords: {offenders[:10]}"

    def test_table_has_full_matrix_coverage(self, table):
        techniques = table["techniques"]
        live = [t for t in techniques.values() if not t.get("status")]
        live_subs = [
            tid for tid, t in techniques.items()
            if "." in tid and not t.get("status")
        ]
        # v19.1 has ~600 live DFIR-tactic techniques; well below this means a
        # build regression that lost whole families.
        assert len(live) >= 550
        assert len(live_subs) >= 350

    def test_meta_version_is_current(self, table):
        version = table["_meta"].get("version", "")
        # v19 is the release that introduced stealth/defense-impairment;
        # anything older reintroduces the T1562-family hole.
        major = version.lstrip("v").split(".")[0]
        assert major.isdigit() and int(major) >= 19, (
            f"table built from ATT&CK {version!r}; rebuild with "
            "tools.mitre.build_mitre_cache from a current bundle"
        )


class TestGateAcceptsSampleIds:
    """End-to-end through the evidence_strength gate component that refuses
    a technique ID the table does not carry."""

    @pytest.mark.parametrize("tid", SAMPLE_TIDS)
    def test_gate_passes(self, tid, monkeypatch):
        import tools.mitre as mitre_mod
        monkeypatch.setattr(mitre_mod, "DEFAULT_TECHNIQUES_PATH", TABLE_PATH)
        import tools.correlate as correlate_mod
        monkeypatch.setattr(correlate_mod, "DEFAULT_MITRE_PATH", TABLE_PATH)

        from tools._gates.mitre_technique_validation import check

        class Ctx:
            description = f"Attacker activity consistent with {tid}."
            confidence = "medium"
            mitre_techniques = [tid]
            validated_techniques = []

        result = check(Ctx())
        assert result is None, f"gate refused {tid}: {result and result.get('error')}"
