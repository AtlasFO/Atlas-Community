"""A directory is scored only as one of the platform's folder artifacts (a
profile's Recent folder, Prefetch, the burn staging folder): a folder named
like a file artifact (System, SAM, History) is no hive and no browser
history. Indexes scored by the older rule are scored again once, in the
writer's path. Invented fixtures (CORP-WS01, jane.doe)."""
from __future__ import annotations

import pytest

from core import contents_index as ci
from core.artifact_value import artifact_score, rank_artifacts


def test_a_directory_scores_only_as_a_folder_artifact():
    assert artifact_score("Program Files/Common Files/System", is_dir=True) == (0, "")
    assert artifact_score("Users/jane.doe/AppData/Local/Google/History", is_dir=True) == (0, "")
    assert artifact_score("Windows/System32/config/SYSTEM")[0] == 82              # the hive file keeps its class
    assert artifact_score("Users/jane.doe/AppData/Roaming/Microsoft/Windows/Recent", is_dir=True)[0] > 0
    assert artifact_score("Program Files/Editor/Recent", is_dir=True) == (0, "")   # not a profile's Recent
    assert artifact_score("Windows/Prefetch", is_dir=True)[0] == 78
    assert artifact_score("C/WINDOWS/prefetch", is_dir=True)[0] == 78            # a label in front, any case


def test_the_srum_rule_names_the_file_not_a_folder_above_it():
    assert artifact_score("Windows/System32/sru/SRUDB.dat")[0] == 76
    assert artifact_score("analysis/srum_out/network_usage.csv")[0] != 76    # a CSV in a folder named so


def test_ranking_a_directory_row_and_a_family_folder():
    plain = {"name": "System", "kind": "directory", "score_as": "Program Files/Common Files/System"}
    family = {"name": "Prefetch", "kind": "directory", "score_as": "TOOL.EXE-0A1B2C3D.pf", "members": ["x"]}
    ranked = rank_artifacts([plain, family])
    assert [r["name"] for r in ranked] == ["Prefetch"]


@pytest.fixture
def con(tmp_path):
    root = tmp_path / "case"
    (root / ".atlas").mkdir(parents=True)
    c = ci._connect(root, create=True)
    ci._insert_entries(c, "CORP-WS01", "evidence/disk/corp-ws01.raw", [
        {"path": "Program Files/Common Files/System", "name": "System", "is_dir": 1, "size": 0},
        {"path": "Windows/Prefetch", "name": "Prefetch", "is_dir": 1, "size": 0},
        {"path": "Windows/System32/config/SYSTEM", "name": "SYSTEM", "size": 100}], "image")
    c.commit()
    yield c
    c.close()


def _scores(c):
    return {r["name"]: (r["score"], r["class"]) for r in c.execute("SELECT name, score, class FROM entries")}


def test_a_listed_folder_named_like_a_hive_has_no_class(con):
    s = _scores(con)
    assert s["System"] == (0, "") and s["Prefetch"][0] == 78 and s["SYSTEM"][0] == 82


def _old_rule(c):
    c.execute("UPDATE entries SET score = 82, class = 'registry hives' WHERE name = 'System'")
    c.execute("UPDATE meta SET value = '{}' WHERE key = 'score_rule'")
    c.commit()


def test_an_index_scored_by_the_old_rule_is_scored_again_once(con):
    _old_rule(con)
    assert ci._rescore_dirs(con) == 1
    assert _scores(con)["System"] == (0, "") and ci._meta_get(con, "score_rule")["version"] == ci.SCORE_RULE
    before = con.total_changes
    assert ci._rescore_dirs(con) == 0 and con.total_changes == before          # the second writes nothing


def test_an_interrupted_rescore_leaves_the_old_scores_and_no_flag(con, monkeypatch):
    _old_rule(con)
    monkeypatch.setattr(ci, "_RESCORE_BATCH", 1)
    calls = []

    def fail_on_second(path, size=None, *, is_dir=False):
        calls.append(path)
        if len(calls) == 2:
            raise RuntimeError("stop")
        return artifact_score(path, size, is_dir=is_dir)
    monkeypatch.setattr("core.artifact_value.artifact_score", fail_on_second)
    with pytest.raises(RuntimeError):
        ci._rescore_dirs(con)
    assert _scores(con)["System"] == (82, "registry hives") and not ci._meta_get(con, "score_rule")


def test_a_volume_listings_directory_row_is_stored_as_a_directory(con):
    join = ci._SuffixJoin(con)
    ci._store_volume_rows(con, "exports/corp-ws01_mft.csv", [
        {"host": "CORP-WS01", "path": "Users/jane.doe/Documents/SAM", "size": "0", "is_dir": True},
        {"host": "CORP-WS01", "path": "Users/jane.doe/AppData/Roaming/Microsoft/Windows/Recent", "size": "0",
         "is_dir": True}], join)
    rows = {r["path"]: (r["is_dir"], r["score"]) for r in con.execute(
        "SELECT path, is_dir, score FROM entries WHERE origin = 'volume'")}
    assert "Users/jane.doe/Documents/SAM" not in rows
    assert rows["Users/jane.doe/AppData/Roaming/Microsoft/Windows/Recent"][0] == 1


def test_an_index_folder_listed_at_size_0_stays_high_value():
    row = {"name": "Recent", "kind": "directory", "size": 0, "index_id": 5,
           "score_as": "Users/jane.doe/AppData/Roaming/Microsoft/Windows/Recent"}
    (ranked,) = rank_artifacts([row])
    assert ranked["score"] > 0 and ranked["empty"] is False
    idle = {"name": "Burn", "kind": "directory", "size": 0,                    # a volume folder: member count 0
            "path": "mnt/host/fs/Users/jane.doe/AppData/Local/Microsoft/Windows/Burn/Burn"}
    assert rank_artifacts([idle])[0]["empty"] is True


def test_a_failed_rescore_still_lists_the_images(tmp_path, monkeypatch):
    import json
    import sqlite3

    import core.execution_log as elog
    root = tmp_path / "case"
    for d in ("evidence/disk", ".atlas", "analysis"):
        (root / d).mkdir(parents=True)
    elog.log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    (root / "evidence/disk/corp-ws01.raw").write_bytes(b"\0" * 512)
    (root / ".atlas" / "mount_plan.json").write_text(json.dumps({"images": [
        {"path": str(root / "evidence/disk/corp-ws01.raw"), "media_role": "disk", "action": "plan_only"}]}),
        encoding="utf-8")
    t = "1924992000"
    body = [f"0|/Windows/System32/config/SYSTEM|300-128-1|r/rrwxrwxrwx|0|0|100|{t}|{t}|{t}|{t}"]

    def run(cmd, timeout):
        cid = elog.log.record_tool_call(cmd=" ".join(cmd), success=True, truncated=False, retries=0, exit_code=0)
        return {"success": True, "stdout": "\n".join(body), "_atlas_call_id": cid, "stderr": ""}
    monkeypatch.setattr(ci, "_run", run)

    def locked(con):
        raise sqlite3.OperationalError("database is locked")
    monkeypatch.setattr(ci, "_rescore_dirs", locked)
    out = ci.build(root)
    assert out["rescore_error"].endswith("database is locked") and out["listed"]
    with ci._connect(root) as con:
        assert not ci._meta_get(con, "score_rule")                     # retried at the next start
