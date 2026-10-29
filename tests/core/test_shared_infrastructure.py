"""Published shared infrastructure (core.shared_infrastructure,
ATLAS_IOC_SHARED_EDGE): the loader, the edge lookup for both address
families, the exact-name vendor and popular lookups, the hunt rule, and the
builder's refusal of a short download. Invented ranges and names only."""
from __future__ import annotations

import json

import pytest

from core import shared_infrastructure as S


@pytest.fixture
def lists(tmp_path, monkeypatch):
    path = tmp_path / "shared_infrastructure.json"
    path.write_text(json.dumps({
        "built": "2031-02-01T00:00:00Z",
        "edges": [{"label": "Example CDN", "networks": ["198.51.100.0/24", "2001:db8:100::/48"]},
                  {"label": "Other Edge", "networks": ["198.51.100.128/25"]}],
        "vendors": {"Example 365 service": ["login.example-vendor.com"]},
        "popular": {"Example popular": ["popular.example.net"]},
    }))
    monkeypatch.setattr(S, "PATH", path)
    S._load.cache_clear()
    yield path
    S._load.cache_clear()


def test_addresses_in_a_published_edge_are_marked(lists):
    assert S.mark("ip", "198.51.100.20") == {"mark": "shared_edge", "label": "Example CDN"}
    assert S.mark("ip", "198.51.100.200")["mark"] == "shared_edge"
    assert S.mark("ip", "2001:db8:100::7")["label"] == "Example CDN"
    assert S.mark("ip", "203.0.113.9") is None


def test_vendor_names_match_exactly_never_by_suffix(lists):
    assert S.mark("domain", "login.example-vendor.com")["mark"] == "vendor_service"
    assert S.mark("url", "https://login.example-vendor.com/common/oauth2")["mark"] == "vendor_service"
    assert S.mark("email", "jane.doe@login.example-vendor.com")["mark"] == "vendor_service"
    assert S.mark("domain", "www.login.example-vendor.com")["mark"] == "vendor_service"
    assert S.mark("domain", "tenant.example-vendor.com") is None
    assert S.mark("domain", "popular.example.net")["mark"] == "popular"


def test_the_hunt_rule_and_the_popular_mark(lists):
    from core.indicators import use_for
    assert use_for("incident", "attacker", "ip", "198.51.100.20") == ["hunt"]
    assert use_for("incident", "attacker", "domain", "login.example-vendor.com") == ["hunt"]
    assert use_for("incident", "attacker", "domain", "tenant.example-vendor.com") == ["block"]
    assert use_for("incident", "attacker", "domain", "popular.example.net") == ["block"]
    assert use_for("incident", "attacker", "ip", "10.0.0.5") == ["hunt", "scope"]
    assert use_for("incident", "attacker", "ip", "203.0.113.9") == ["block"]


def test_the_switch_off_marks_nothing(lists, monkeypatch):
    monkeypatch.setenv("ATLAS_IOC_SHARED_EDGE", "0")
    from core.indicators import use_for
    assert S.mark("ip", "198.51.100.20") is None
    assert use_for("incident", "attacker", "ip", "198.51.100.20") == ["block"]


def test_a_missing_file_warns_once_and_marks_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(S, "PATH", tmp_path / "absent.json")
    monkeypatch.setattr(S, "_WARNED", [False])
    S._load.cache_clear()
    assert S.mark("ip", "198.51.100.20") is None and S.missing()
    assert S.mark("ip", "198.51.100.21") is None
    assert capsys.readouterr().err.count("shared infrastructure list missing") == 1
    S._load.cache_clear()


def test_the_builder_refuses_a_short_download(monkeypatch, tmp_path):
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "build_si", Path(__file__).resolve().parents[2] / "devtools" / "build_shared_infrastructure.py")
    B = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(B)
    monkeypatch.setattr(B, "_get", lambda url: b"198.51.100.0/24\n")
    monkeypatch.setattr(B, "_json", lambda url: {})
    out = tmp_path / "si.json"
    monkeypatch.setattr("sys.argv", ["build", "--out", str(out)])
    assert B.main() == 1 and not out.exists()


def test_the_vendored_file_is_present_and_readable():
    S._load.cache_clear()
    data = S._load(str(S.PATH))
    assert data is not None and data["ranges"][4] and data["vendors"]
    assert not data["popular"]      # the popular set stays empty until its terms are settled


def test_no_case_identifiers_are_baked_into_the_loader_or_the_builder():
    """The loader and the builder carry public sources and their labels
    only: no host, account, address or date of any case."""
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    for rel in ("core/shared_infrastructure.py", "devtools/build_shared_infrastructure.py"):
        src = (root / rel).read_text()
        code = re.sub(r'"""(?:.|\n)*?"""', "", src)
        code = "\n".join(line for line in code.splitlines() if not line.lstrip().startswith("#")).lower()
        assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", code), rel
        assert not re.search(r"\b20\d{2}-\d{2}-\d{2}\b", code), rel
        for token in ("corp-ws", "jane.doe", "corp\\"):
            assert token not in code, rel
