"""Attribution is mechanical, not remembered: anything vendored into the
tree has to be named in NOTICE, and no typeface is shipped or declared for
download without a licence review."""
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]


def _read(name: str) -> str:
    return (_ROOT / name).read_text(encoding="utf-8")


class TestVendoredFilesAreCredited:
    def test_every_vendored_file_is_named_in_notice(self):
        """A new file under dashboard/vendor/ is redistributed by this repo,
        so its licence and copyright holder belong in NOTICE. Adding one
        without a notice entry fails here rather than in someone's audit."""
        notice = _read("NOTICE")
        vendored = sorted(p for p in (_ROOT / "dashboard" / "vendor").rglob("*")
                          if p.is_file())
        assert vendored, "no vendored files found — did the path move?"
        missing = [str(p.relative_to(_ROOT)) for p in vendored
                   if str(p.relative_to(_ROOT)) not in notice]
        assert not missing, (
            f"vendored but not credited in NOTICE: {missing}. Add the file, "
            f"its licence and its copyright holder to NOTICE.")

    def test_bundled_mitre_data_carries_the_required_statement(self):
        """ATT&CK content is reproduced in share/.common/ — MITRE's terms
        require this exact statement to travel with it."""
        # Line wrapping is free; the sentence is not.
        notice = " ".join(_read("NOTICE").split())
        assert "The MITRE Corporation" in notice
        assert ("This work is reproduced and distributed with the permission "
                "of The MITRE Corporation.") in notice
        for name in ("mitre_techniques.json", "mitre_groups.json",
                     "mitre_software.json", "mitre_mitigations.json"):
            assert name in notice

    def test_notice_names_the_bundled_attack_version(self):
        """The version in NOTICE is the version in the tables — a rebuild
        that forgets NOTICE fails here."""
        import json
        notice = _read("NOTICE")
        version = json.load(open(_ROOT / "share" / ".common" / "mitre_techniques.json"))["_meta"]["version"]
        assert f"version {version}" in notice

    def test_notice_still_credits_the_code_atlas_was_built_from(self):
        notice = _read("NOTICE")
        assert "MIT License" in notice          # the base tool
        assert "Apache License, Version 2.0" in notice   # ported portions
        for cited in ("core/evidence_index.py", "tools/coverage_audit.py",
                      "tools/export_tools.py"):
            assert cited in notice
            assert (_ROOT / cited).is_file(), (
                f"NOTICE credits {cited}, which no longer exists — the "
                f"attribution has to follow the code that moved.")


def _tracked_files() -> list[str]:
    """The files git tracks, which is exactly what the repository
    distributes. A working copy may hold untracked local material, and that
    is not what an audit of this repository sees."""
    import subprocess
    try:
        listing = subprocess.run(
            ["git", "ls-files", "-z"], cwd=_ROOT, check=True,
            capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.skip("no git checkout to enumerate")
    return [rel for rel in listing.split("\0") if rel]


class TestNoFontIsShipped:
    """The dashboard and the reports render with system font stacks. A
    typeface reaches users only as a shipped font file or through an
    @font-face rule that fetches one; either needs a licence review and a
    NOTICE entry first, so neither may slip in through a copy-paste."""

    _FONT_SUFFIXES = (".woff", ".woff2", ".ttf", ".otf", ".eot")

    def test_no_font_files_are_vendored(self):
        fonts = list((_ROOT / "dashboard" / "vendor").rglob("*.woff*")) + \
            list((_ROOT / "dashboard" / "vendor").rglob("*.[ot]tf"))
        assert not fonts, f"font files vendored again: {fonts}"

    def test_no_font_file_is_tracked_anywhere(self):
        fonts = [rel for rel in _tracked_files()
                 if Path(rel).suffix.lower() in self._FONT_SUFFIXES]
        assert not fonts, f"font files in the tree: {fonts}"

    def test_nothing_tracked_declares_a_font_face(self):
        hits = []
        for rel in _tracked_files():
            if rel == "tests/core/test_attribution_files.py":
                continue
            path = _ROOT / rel
            if path.suffix not in (".html", ".css", ".js", ".py"):
                continue
            try:
                if "@font-face" in path.read_text(encoding="utf-8", errors="ignore").lower():
                    hits.append(rel)
            except OSError:
                continue
        assert not hits, f"@font-face declared in: {hits}"


class TestThirdPartyInventory:
    def test_it_records_the_open_licence_questions(self):
        """The inventory is where a decision that was deferred stays
        visible; losing these lines loses the decision."""
        text = _read("THIRD-PARTY.md")
        assert "Volatility Software License" in text
        assert "LGPL" in text
        assert "not affiliated with" in text

    def test_license_and_readme_point_at_both_files(self):
        for name in ("LICENSE", "README.md"):
            text = _read(name)
            assert "NOTICE" in text and "THIRD-PARTY.md" in text, name
