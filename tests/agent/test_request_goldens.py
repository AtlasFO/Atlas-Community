"""Request goldens: what Atlas sends for each provider preset, pinned.

tests/fixtures/llm_requests/<preset>.json holds the requests captured by
devtools/provider_profiles/capture_requests.py on the code from before the
presets moved to provider_profiles/; anthropic-compat.json is the capture of
the preset then called anthropic (Anthropic's OpenAI-compatible layer).
anthropic.json, the native Messages profile, did not exist then: it is the
capture of the code that added it. Every scenario runs again here on the
current code. A body is compared as the string sent, key order included (a
byte change breaks a provider's prefix cache); headers by name and value.
A record may differ from the capture only as CHANGED says, each with its
reason, so every intended byte change is listed here.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests._edition import require_devtools

require_devtools()

from devtools.provider_profiles import capture_requests as cap  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "llm_requests"
PRESETS = sorted(p.stem for p in FIXTURES.glob("[a-z]*.json"))
CELL = ("model:z-ai/glm-5.2", "model:qwen/qwen3.8-flash")   # the models Atlas runs most, on openrouter

# The intended changes, each with its reason.
B3 = ("An instance named like a profile in other letter case binds that profile, as one bound by "
      "_PRESET does: the request equals the one of the same scenario bound by _PRESET.")
K3 = ("The anthropic profile's [headers] (anthropic-version) go on every request; before, only "
      "the model list carried it.")
C8 = ("The context probe sends the provider's own headers: Anthropic's model list answers only with its "
      "version header, and its window (max_input_tokens) is read before its output cap (max_tokens).")
PAGES = ("Anthropic's model list is read in pages of up to 1000 (limit, then after_id while has_more), so a "
         "model past the first page is found: every model-list request asks for limit=1000.")
D1 = ("The OpenAI-compatible Anthropic layer gets no thinking budget any more (Claude models from Opus 4.7 on "
      "refuse one): the thinking field is gone, so a scripted refusal of it can no longer be adapted away.")
D3 = ("An instance named anthropic no longer gets cache markers by that name (the compatible layer ignores "
      "them; the native profile places its own): the request equals the one bound by _PRESET.")
B1 = ("A provider bound to the fallback profile (registered as Other) at Anthropic's host no longer gets "
      "anthropic-version on its model-list requests: profiles are never bound by host; doctor names the "
      "_PRESET that binds it.")


def _golden(preset: str) -> dict[str, dict]:
    data = json.loads((FIXTURES / f"{preset}.json").read_text(encoding="utf-8"))
    return {r["scenario"]: r for r in data["records"]}


def _expected(preset: str, scenario: str, golden: dict[str, dict]) -> tuple[dict, str]:
    """The record the current code must produce, and why it differs from the capture."""
    record, why = golden[scenario], ""
    same = {"name_mixed": "analyst_tools", "name_mixed_effort": "effort_high"}.get(scenario)
    if same and golden[scenario]["requests"] != golden[same]["requests"]:
        record, why = golden[same], B3
    if preset == "anthropic-compat" and scenario == "name_lower" \
            and golden[scenario]["requests"] != golden["analyst_tools"]["requests"]:
        record, why = golden["analyst_tools"], D3
    if scenario.startswith("fallback_at_anthropic:"):
        requests = [dict(r, headers={k: v for k, v in r["headers"].items() if k != "anthropic-version"})
                    for r in record["requests"]]
        if requests != record["requests"]:
            record, why = dict(record, requests=requests), B1
    if preset == "anthropic-compat" and scenario != "context_probe":
        requests = [dict(r, headers={**r["headers"], "anthropic-version": "2023-06-01"})
                    for r in record["requests"]]
        if requests != record["requests"]:
            record, why = dict(record, requests=requests), (why + " " + K3).strip()
    if preset in ("anthropic", "anthropic-compat") and scenario == "context_probe":
        requests = [dict(r, headers={**r["headers"], "anthropic-version": "2023-06-01"})
                    for r in record["requests"]]
        if requests != record["requests"]:
            record, why = dict(record, requests=requests), (why + " " + C8).strip()
    if preset in ("anthropic", "anthropic-compat"):
        requests = [dict(r, url=r["url"] + "?limit=1000") if r["method"] == "GET" else r
                    for r in record["requests"]]
        if requests != record["requests"]:
            record, why = dict(record, requests=requests), (why + " " + PAGES).strip()
    if preset == "anthropic-compat":
        requests = [dict(r, body=_without(r["body"], "thinking")) for r in record["requests"]]
        if requests != record["requests"]:
            if scenario == "adapt_400_thinking":
                record = dict(record, requests=requests[:1], error="LLMStatusError")
            else:
                record = dict(record, requests=requests)
            why = (why + " " + D1).strip()
    return record, why


def _without(body: str | None, key: str) -> str | None:
    """A sent body without one top-level key, serialized as the recorder does."""
    if body is None:
        return None
    data = json.loads(body)
    data.pop(key, None)
    return json.dumps(data, ensure_ascii=False)


def _compare(record: dict) -> list:
    return [(r["method"], r["url"], r["headers"], r["body"]) for r in record["requests"]] + \
        [record.get("error", "")]


@pytest.fixture(scope="module")
def replayed():
    return cap.capture(PRESETS)


@pytest.mark.parametrize("preset", PRESETS)
def test_every_request_is_the_captured_one_or_an_intended_change(replayed, preset):
    golden = _golden(preset)
    now = {r["scenario"]: r for r in replayed[preset]["records"]}
    assert sorted(now) == sorted(golden)
    for scenario in golden:
        expected, why = _expected(preset, scenario, golden)
        assert _compare(now[scenario]) == _compare(expected), f"{preset}/{scenario} {why}"


def test_the_intended_changes_are_these_and_never_touch_the_most_used_models():
    changed = {(p, s): why for p in PRESETS for s in _golden(p)
               if (why := _expected(p, s, _golden(p))[1])}
    assert not [k for k in changed if k[0] == "openrouter" and k[1] in CELL]
    assert {k for k, why in changed.items() if B3 in why} == {
        ("anthropic-compat", "name_mixed"),
        *((p, "name_mixed_effort") for p in ("anthropic-compat", "deepseek", "meta", "openrouter", "qwen", "zai"))}
    assert {k[0] for k, why in changed.items() if K3 in why} == {"anthropic-compat"}
    assert {k for k, why in changed.items() if D1 in why} == {
        ("anthropic-compat", s) for s in ("pin_low", "effort_high", "effort_minimal", "effort_none",
                                          "name_mixed_effort", "adapt_400_level", "adapt_400_thinking")}
    assert {k for k, why in changed.items() if D3 in why} == {("anthropic-compat", "name_lower")}
    assert {k for k, why in changed.items() if C8 in why} == {("anthropic", "context_probe"),
                                                             ("anthropic-compat", "context_probe")}
    assert {k[0] for k, why in changed.items() if PAGES in why} == {"anthropic", "anthropic-compat"}
    assert all(C8 in why or PAGES in why for k, why in changed.items() if k[0] == "anthropic")  # else as captured
    assert {k for k, why in changed.items() if B1 in why} == {
        ("custom", f"fallback_at_anthropic:{call}") for call in (
            "test_connection", "list_models", "doctor_probe", "provider_use", "dashboard_probe",
            "dashboard_probe_edit", "wizard_probe")}


@pytest.mark.parametrize("broken", ['schema = 1\nid = "openrouter"\nlabel = \n',
                                    'schema = 1\nid = "openrouter"\nbogus = 1\n',
                                    'schema = 1\nid = "other"\n'])
def test_a_broken_profile_leaves_every_other_provider_byte_identical(tmp_path, broken):
    """A user file that fails stops only the instances bound to its id."""
    (tmp_path / "openrouter.toml").write_text(broken, encoding="utf-8")
    golden = _golden("deepseek")
    now = {r["scenario"]: r for r in cap.capture(["deepseek"], user_profiles=tmp_path)["deepseek"]["records"]}
    for scenario in ("analyst_tools", "effort_high", "test_connection"):
        assert _compare(now[scenario]) == _compare(_expected("deepseek", scenario, golden)[0])
    refused = cap.capture(["openrouter"], user_profiles=tmp_path)["openrouter"]["records"]
    assert all(r["requests"] == [] and r.get("error") for r in refused
               if r["scenario"] in ("analyst_tools", "test_connection"))
