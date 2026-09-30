"""The report's narrative sections go over the shared transport.

They used to build their own request: no limit parameter at all, so the
endpoint's own default decided how long a section could run; temperature sent
whether or not the endpoint accepts it; and a 400 ended the call instead of
teaching a retry. These tests hold that path on the shared client, and pin the
two failure modes that must reach the caller's deterministic fallback rather
than produce a blank or half-written section.
"""
import httpx
import pytest

from core import llmhub, providers, report_projection


class _Resp:
    def __init__(self, body, status=200):
        self._body, self.status_code, self.text = body, status, ""

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._body


def _chat(content="Some narrative prose.", finish="stop"):
    return {"choices": [{"message": {"role": "assistant", "content": content},
                         "finish_reason": finish}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5}}


class _Provider:
    name = "llmhub"
    model = "a-model"
    base_url = "https://endpoint.example/v1"
    api_key = "k"

    def headers(self):
        return {"Authorization": "Bearer k"}

    def chat_url(self):
        return "https://endpoint.example/v1/chat/completions"


@pytest.fixture
def sent(monkeypatch, tmp_path):
    """Capture the request the section generator sends."""
    captured: dict = {}
    # The generator imports core.providers inside the function, so the
    # substitution has to land on the source module, not on a name this one
    # never bound.
    monkeypatch.setattr(providers, "resolve", lambda *a, **k: _Provider())
    monkeypatch.setattr(providers, "role_name", lambda *a, **k: "llmhub")
    # A fresh compat cache: what earlier tests taught the client about
    # "a-model" must not shape this request.
    from agent import llm as _llm
    monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "compat.json"))
    monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
    _llm.clear_api_compat_cache(memory_only=True)
    for var in ("ATLAS_EFFORT_REPORT", "ATLAS_REPORT_SECTION_MAX_TOKENS"):
        monkeypatch.delenv(var, raising=False)

    def _post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["body"] = json or {}
        return _Resp(captured.get("reply") or _chat())

    monkeypatch.setattr(httpx, "post", _post)
    return captured


def _generate(**ctx):
    context = {"section_id": "findings", "title": "Findings", "style": "plain",
               "report_scope": "case", "report_host": "", "conflicts": [],
               "report_language": "en", "conclusions": [], "claims": [], **ctx}
    return report_projection.default_llm_section_generator(
        context, {"id": "findings", "title": "Findings"})


class TestRequestShape:
    def test_no_cap_unless_the_operator_sets_a_ceiling(self, sent, monkeypatch):
        """A thinking model pays its thinking out of the completion limit;
        every fixed cap starved one. The endpoint's own default decides
        unless the operator states a ceiling."""
        _generate()
        body = sent["body"]
        assert "max_tokens" not in body and "max_completion_tokens" not in body
        monkeypatch.setenv("ATLAS_LLM_MAX_OUTPUT_TOKENS", "4096")
        _generate()
        assert sent["body"].get("max_tokens") == 4096

    def test_temperature_survives_the_move(self, sent):
        """A low temperature is why this path set one: prose about evidence
        should not embroider. Moving to the shared client must not drop it."""
        _generate()
        assert sent["body"]["temperature"] == pytest.approx(0.2)

    def test_the_role_is_named_so_a_level_can_be_set_for_it(self, sent,
                                                            monkeypatch):
        monkeypatch.setenv("ATLAS_EFFORT_REPORT", "low")
        _generate()
        assert sent["body"]["reasoning_effort"] == "low"

    def test_no_level_configured_sends_none(self, sent):
        _generate()
        assert "reasoning_effort" not in sent["body"]

    def test_an_endpoint_that_refuses_temperature_still_gets_a_section(
            self, sent, monkeypatch):
        """The shared client drops an option the endpoint rejected and sends
        again. Before, such a 400 ended the call and lost the section."""
        from agent import llm as _llm
        _llm.remember_api_compat(
            "llmhub", "a-model",
            _llm.ApiCompatProfile(send_temperature=False), persist=False)
        assert _generate()
        assert "temperature" not in sent["body"]


class TestFailuresReachTheFallback:
    def test_an_empty_reply_raises_rather_than_returning_nothing(self, sent):
        """A model that spent its budget thinking returns no content. A blank
        section is worse than the deterministic one the caller falls back to."""
        sent["reply"] = _chat(content="", finish="length")
        with pytest.raises(RuntimeError):
            _generate()

    def test_a_truncated_reply_raises_rather_than_half_a_sentence(self, sent):
        sent["reply"] = _chat(content="This section stops mid-", finish="length")
        with pytest.raises(RuntimeError, match="cut off"):
            _generate()

    def test_a_complete_reply_is_returned(self, sent):
        sent["reply"] = _chat(content="A finished paragraph.", finish="stop")
        assert _generate() == "A finished paragraph."
