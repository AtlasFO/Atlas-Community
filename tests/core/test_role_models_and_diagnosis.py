"""Every role's model is resolvable by one rule, and an extractor's
complaint is turned into a diagnosis the model can act on."""
import io
import zipfile

import pytest

from core.providers import role_models
from tools.archives import diagnose_extraction, zip_extract


@pytest.fixture
def one_provider(monkeypatch):
    for var in ("ATLAS_AGENT_MODEL", "REASON_MODEL", "DAIR_MODEL", "ATLAS_REVIEW_MODEL",
                "ATLAS_AGENT_PROVIDER", "REASON_BACKEND", "DAIR_BACKEND",
                "ATLAS_REPORT_PROVIDER", "ATLAS_REVIEW_PROVIDER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ATLAS_PROVIDERS", "alpha,beta")
    for name, model in (("ALPHA", "vendor/alpha-model"), ("BETA", "vendor/beta-model")):
        monkeypatch.setenv(f"ATLAS_PROVIDER_{name}_BASE_URL", "https://example.invalid/v1")
        monkeypatch.setenv(f"ATLAS_PROVIDER_{name}_API_KEY", "k")
        monkeypatch.setenv(f"ATLAS_PROVIDER_{name}_MODEL", model)


def test_explicit_model_variables_outrank_the_provider(one_provider, monkeypatch):
    monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "alpha")
    monkeypatch.setenv("REASON_BACKEND", "beta")
    monkeypatch.setenv("DAIR_BACKEND", "beta")
    monkeypatch.setenv("ATLAS_REVIEW_PROVIDER", "beta")
    roles = role_models()
    assert roles["analyst"] == "vendor/alpha-model"
    assert roles["reason"] == "vendor/beta-model" and roles["dair"] == "vendor/beta-model"
    assert roles["report"] == "vendor/alpha-model"   # falls back to the agent provider
    assert roles["review"] == "vendor/beta-model"

    monkeypatch.setenv("ATLAS_AGENT_MODEL", "vendor/explicit-analyst")
    monkeypatch.setenv("DAIR_MODEL", "vendor/explicit-dair")
    monkeypatch.setenv("ATLAS_REVIEW_MODEL", "vendor/explicit-review")
    roles = role_models()
    assert roles["analyst"] == "vendor/explicit-analyst"
    assert roles["dair"] == "vendor/explicit-dair"
    assert roles["review"] == "vendor/explicit-review"
    assert roles["reason"] == "vendor/beta-model"


def test_reviewer_provider_outranks_reason_model(one_provider, monkeypatch):
    """The recorded reviewer model is the one agent/review.py resolves: its
    own provider before REASON_MODEL, which belongs to the reason role."""
    monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "alpha")
    monkeypatch.setenv("REASON_BACKEND", "alpha")
    monkeypatch.setenv("REASON_MODEL", "vendor/explicit-reason")
    monkeypatch.setenv("ATLAS_REVIEW_PROVIDER", "beta")
    roles = role_models()
    assert roles["reason"] == "vendor/explicit-reason"
    assert roles["review"] == "vendor/beta-model"


def test_unconfigured_roles_are_empty_not_guessed(one_provider):
    roles = role_models()
    assert roles == {"analyst": "", "reason": "", "dair": "", "report": "", "review": ""}


def test_structural_damage_wins_over_the_password_guess():
    text = ("ERRORS:\nHeaders Error\nUnconfirmed start of archive\n"
            "ERROR: Data Error in encrypted file. Wrong password? : a.jpg")
    assert diagnose_extraction(text)[0] == "misaligned_carve"
    assert diagnose_extraction("ERROR: Wrong password : a.jpg")[0] == "wrong_password"
    assert diagnose_extraction("Unexpected end of archive")[0] == "truncated"
    assert diagnose_extraction("all fine") == ("", "")


def test_zip_with_a_damaged_member_header_is_diagnosed(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "hello")
    raw = bytearray(buf.getvalue())
    raw[0:2] = b"XX"  # the local file header no longer starts where the directory says
    archive = tmp_path / "carved.zip"
    archive.write_bytes(bytes(raw))
    result = zip_extract(str(archive), str(tmp_path / "out"))
    assert result["success"] is False
    assert result.get("diagnosis") == "misaligned_carve"
    assert "password" in result["next_step"].lower()
