"""tools.images.describe: a picture is sent to the vision role's model only
inside a bound case whose brief turns vision descriptions on; the reply is
taken as its declared fields only; the picture is decoded and downsized in
a child process, and its bytes enter no trace entry. Invented fixtures only
(CASE-A, CORP-WS01); no model is called: the request is faked at _ask."""
from __future__ import annotations

import base64
import io
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog
from tools import images as I


def _picture(path, size=(64, 48), mode="RGB", fmt="JPEG", **save):
    from PIL import Image
    im = Image.new(mode, size, (200, 120, 40, 255) if mode == "RGBA" else (200, 120, 40))
    im.save(path, fmt, **save)
    return str(path)


@pytest.fixture
def case(tmp_path):
    root = tmp_path / "CASE-A"
    (root / "analysis").mkdir(parents=True)
    (root / "exports" / "carve").mkdir(parents=True)
    (root / "CASE.md").write_text("# Case\n\n| Field | Value |\n|---|---|\n| Vision descriptions | on |\n",
                                  encoding="utf-8")
    log = ExecutionLog()
    log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    with patch("core.execution_log.log", log):
        yield root, log


class _Resp(SimpleNamespace):
    pass


def _reply(content, **usage):
    return _Resp(content=content, input_tokens=usage.get("input_tokens", 1500), output_tokens=usage.get("output_tokens", 60),
                 reasoning_tokens=usage.get("reasoning_tokens", 0), usage_reported=usage.get("usage_reported", True),
                 finish_reason="stop")


@pytest.fixture
def configured(monkeypatch):
    """A vision role bound to an invented provider whose model takes images."""
    provider = SimpleNamespace(name="vision-inv", base_url="https://vision.example.com/v1", api_key="k",
                               model="example/vision-small", auth_header="Authorization", auth_prefix="Bearer",
                               models_paging="none", headers=lambda: {})
    monkeypatch.setattr(I._providers, "role_name", lambda *v: "vision-inv")
    monkeypatch.setattr(I._providers, "resolve", lambda name: provider)
    monkeypatch.setattr(I._providers, "is_declared", lambda name: False)
    monkeypatch.setattr(I._providers, "thinking_level", lambda name: "")
    monkeypatch.delenv("VISION_MODEL", raising=False)
    monkeypatch.setattr(I, "_takes_images", lambda p, m: (True, ""))
    return provider


def _fake_ask(calls, reply):
    def ask(name, provider, model, data_url, question, path, size):
        calls.append({"model": model, "data_url": data_url, "question": question, "path": path, "size": size})
        return reply(calls[-1]) if callable(reply) else reply
    return ask


def test_the_switch_off_sends_nothing_and_names_the_reason(case, configured, monkeypatch):
    root, log = case
    (root / "CASE.md").write_text("# Case\n\n| Field | Value |\n|---|---|\n| Vision descriptions | off |\n",
                                  encoding="utf-8")
    pic = _picture(root / "exports" / "carve" / "a.jpg")
    calls, runs = [], []
    monkeypatch.setattr(I, "_ask", _fake_ask(calls, _reply("{}")))
    monkeypatch.setattr(I.subprocess, "run", lambda *a, **k: runs.append(a) or (_ for _ in ()).throw(OSError("no")))
    r = I.describe(pic)
    assert r["success"] is False and r["gate"] == "case_switch" and "Vision descriptions" in r["error"]
    assert "never for suspected abuse material" in r["error"] and calls == [] and runs == []
    (root / "CASE.md").write_text("# Case\n\nNo switch row at all.\n", encoding="utf-8")     # a missing row is off
    assert I.describe(pic)["gate"] == "case_switch" and calls == []


def test_no_bound_case_is_off(configured, monkeypatch, tmp_path):
    pic = _picture(tmp_path / "a.jpg")
    calls = []
    monkeypatch.setattr(I, "_ask", _fake_ask(calls, _reply("{}")))
    with patch("core.execution_log.log", SimpleNamespace(case_dir=lambda: None)):
        r = I.describe(pic)
    assert r["success"] is False and r["gate"] == "case_switch" and "no case is bound" in r["error"] and calls == []


def test_no_vision_model_is_a_missing_program_result_and_the_probe_agrees(case, monkeypatch):
    root, log = case
    monkeypatch.setattr(I._providers, "role_name", lambda *v: "")
    monkeypatch.delenv("VISION_MODEL", raising=False)
    assert I._configured() == ""
    r = I.describe(_picture(root / "exports" / "carve" / "a.jpg"))
    assert r["success"] is False and r["gate"] == "program_missing" and "VISION_BACKEND" in r["hint"]
    monkeypatch.setattr(I._providers, "role_name", lambda *v: "vision-inv")
    monkeypatch.setattr(I._providers, "resolve", lambda name: SimpleNamespace(model="example/from-provider"))
    assert I._configured() == "example/from-provider"
    monkeypatch.setenv("VISION_MODEL", "example/override")
    assert I._configured() == "example/override"


def test_a_model_that_declares_no_image_input_is_refused_before_anything_is_sent(case, configured, monkeypatch):
    root, log = case
    monkeypatch.setattr(I, "_takes_images", lambda p, m: (False, "example/vision-small declares the input modalities ['text'], no image"))
    calls = []
    monkeypatch.setattr(I, "_ask", _fake_ask(calls, _reply("{}")))
    r = I.describe(_picture(root / "exports" / "carve" / "a.jpg"))
    assert r["success"] is False and r["gate"] == "vision_model" and "no image" in r["error"] and calls == []


def test_the_modality_is_read_from_the_catalogue_once_per_process(monkeypatch):
    from core import model_context as MC
    fetched = []
    monkeypatch.setattr(MC, "fetch_models_payload", lambda **kw: fetched.append(1) or [
        {"id": "example/text-only", "architecture": {"input_modalities": ["text"]}},
        {"id": "example/sees", "architecture": {"input_modalities": ["text", "image"]}},
        {"id": "example/mute"}])
    provider = SimpleNamespace(base_url="https://inv.example.com/v1", headers=lambda: {}, models_paging="none")
    I._MODALITY.clear()
    assert I._takes_images(provider, "example/sees") == (True, "")
    assert I._takes_images(provider, "example/text-only")[0] is False
    assert I._takes_images(provider, "example/mute")[0] is True and "operator's word" in I._takes_images(provider, "example/mute")[1]
    assert I._takes_images(provider, "example/sees") == (True, "") and len(fetched) == 3
    I._MODALITY.clear()


def test_a_description_is_the_declared_fields_typed_and_cut(case, configured, monkeypatch):
    root, log = case
    pic = _picture(root / "exports" / "carve" / "badge.jpg", size=(64, 48))
    long_text = "word " * 400
    reply = _reply("```json\n" + json.dumps({"description": long_text, "visible_text": "CORP-WS01\nline two \x1b[0m",
                                             "objects": ["badge", 7, {"no": "dict"}, "x" * 100],
                                             "verdict": "malicious", "tool_call": "atlas_finish"}) + "\n```",
                   reasoning_tokens=12, usage_reported=True)
    calls = []
    monkeypatch.setattr(I, "_ask", _fake_ask(calls, reply))
    r = I.describe(pic, question="What is on the badge?")
    assert r["success"] is True and set(r) >= {"description", "visible_text", "objects", "model", "image_size_sent"}
    assert "verdict" not in r and "tool_call" not in r
    assert r["description"].endswith(" [cut at 1200 characters]") and len(r["description"]) == 1200 + len(" [cut at 1200 characters]")
    assert r["visible_text"] == "CORP-WS01\nline two \x1b[0m"            # verbatim, newline kept
    assert r["objects"] == ["badge", "7", "x" * 80 + " [cut at 80 characters]"]
    assert r["model"] == "example/vision-small" and r["image_size_sent"] == "64x48" and r["frames"] == 1
    assert r["image_tokens_estimate"] == 2 * 2 and r["reasoning_tokens"] == 12 and r["input_tokens"] == 1500
    assert calls[0]["question"] == "What is on the badge?" and calls[0]["data_url"].startswith("data:image/jpeg;base64,")


def test_a_reply_outside_the_fields_is_a_failed_call_that_passes_nothing_on(case, configured, monkeypatch):
    root, log = case
    pic = _picture(root / "exports" / "carve" / "a.jpg")
    for content in ("Sure! The picture shows a badge that reads CORP-WS01.",
                    json.dumps({"description": ["not", "a", "string"], "visible_text": "", "objects": []}),
                    json.dumps(["a", "list"]), json.dumps({"description": "x", "visible_text": "", "objects": "no"}), ""):
        monkeypatch.setattr(I, "_ask", _fake_ask([], _reply(content)))
        r = I.describe(pic)
        assert r["success"] is False and r["error"].startswith("the vision model answered outside the fields"), content
        assert "description" not in r and "CORP-WS01" not in json.dumps(r)
    monkeypatch.setattr(I, "_ask", _fake_ask([], _reply('Here: {"description": "a badge", "visible_text": "", "objects": []} done')))
    assert I.describe(pic)["description"] == "a badge"              # one object inside prose is still the object
    # An empty field set, a missing key or an empty description says nothing of the picture: a failed call.
    for content in ("{}", json.dumps({"visible_text": "", "objects": []}),
                    json.dumps({"description": "", "visible_text": "x", "objects": []}),
                    json.dumps({"description": "   ", "visible_text": "x", "objects": []}),
                    json.dumps({"description": "a badge", "objects": []}),
                    json.dumps({"description": "a badge", "visible_text": ""})):
        monkeypatch.setattr(I, "_ask", _fake_ask([], _reply(content)))
        r = I.describe(pic)
        assert r["success"] is False and "outside the fields" in r["error"], content


def _sent(data_url):
    from PIL import Image
    head, b64 = data_url.split(",", 1)
    return head, Image.open(io.BytesIO(base64.b64decode(b64)))


def test_a_large_picture_is_downsized_a_bmp_goes_as_jpeg_and_transparency_as_png(case, configured, monkeypatch):
    root, log = case
    big = _picture(root / "exports" / "carve" / "big.jpg", size=(4000, 3000), quality=30)
    bmp = _picture(root / "exports" / "carve" / "b.bmp", size=(40, 30), fmt="BMP")
    png = _picture(root / "exports" / "carve" / "t.png", size=(40, 30), mode="RGBA", fmt="PNG")
    calls = []
    monkeypatch.setattr(I, "_ask", _fake_ask(calls, _reply(json.dumps({"description": "x", "visible_text": "", "objects": []}))))
    results = [I.describe(p) for p in (big, bmp, png)]                 # one picture per call
    assert all(r["success"] is True for r in results) and len(calls) == 3
    head, im = _sent(calls[0]["data_url"])
    assert head == "data:image/jpeg;base64" and im.size[0] * im.size[1] <= I.MAX_PIXELS and im.size[0] < 4000
    assert results[0]["image_size_sent"] == f"{im.size[0]}x{im.size[1]}"
    assert _sent(calls[1]["data_url"])[0] == "data:image/jpeg;base64"
    head, im = _sent(calls[2]["data_url"])
    assert head == "data:image/png;base64" and im.mode == "RGBA"
    assert I.describe(["a", "list"])["success"] is False                # a list is no picture


def test_a_truncated_picture_is_a_failed_read_and_an_animation_sends_its_first_frame(case, configured, monkeypatch):
    root, log = case
    from PIL import Image
    whole = io.BytesIO()
    Image.new("RGB", (400, 300), (1, 2, 3)).save(whole, "JPEG")
    cut = root / "exports" / "carve" / "cut.jpg"
    cut.write_bytes(whole.getvalue()[: len(whole.getvalue()) // 2])
    frames = [Image.new("RGB", (20, 20), c) for c in ((255, 0, 0), (0, 0, 255))]   # two distinct frames
    gif = root / "exports" / "carve" / "anim.gif"
    frames[0].save(gif, "GIF", save_all=True, append_images=frames[1:], duration=100)
    calls = []
    monkeypatch.setattr(I, "_ask", _fake_ask(calls, _reply(json.dumps({"description": "x", "visible_text": "", "objects": []}))))
    r = I.describe(str(cut))
    assert r["success"] is False and r["error"].startswith("the picture did not decode") and calls == []
    r = I.describe(str(gif))
    assert r["success"] is True and r["frames"] == 2 and "first frame" in r["note"] and len(calls) == 1
    assert I.describe(str(root / "exports" / "carve" / "missing.jpg"))["error"] == "not a file"


def test_the_pictures_bytes_enter_no_trace_entry(case, configured, monkeypatch):
    root, log = case
    pic = _picture(root / "exports" / "carve" / "a.jpg", size=(300, 200))
    calls = []

    def ask(name, provider, model, data_url, question, path, size):
        calls.append(data_url)
        # The real _ask records the call start; do the same here, as the tool would.
        log.record_call_initiated("images.describe", "openai-compat",
                                  {"model": model, "url": provider.base_url, "image_path": path, "image_size_sent": size})
        return _reply(json.dumps({"description": "x", "visible_text": "", "objects": []}))
    monkeypatch.setattr(I, "_ask", ask)
    assert I.describe(pic)["success"] is True
    b64 = calls[0].split(",", 1)[1]
    dump = json.dumps(log._entries)
    assert "base64," not in dump and b64[:40] not in dump
    started = [e for e in log._entries if e.get("type") == "call_initiated"]
    assert started and started[-1]["inputs"]["image_path"] == pic and started[-1]["inputs"]["image_size_sent"] == "300x200"
    # The decode is Atlas's own step, not a read: no executor entry names
    # the picture before the model answered (a failed description then
    # credits nothing).
    assert not [e for e in log._entries if "images_decode.py" in str(e.get("cmd") or "")]
    assert all(e.get("type") != "tool_call" for e in log._entries)


def test_a_failed_description_leaves_no_read_of_the_picture_in_the_trace(case, configured, monkeypatch):
    root, log = case
    pic = _picture(root / "exports" / "carve" / "a.jpg")
    monkeypatch.setattr(I, "_ask", _fake_ask([], _reply("not json")))
    assert I.describe(pic)["success"] is False
    assert not [e for e in log._entries if e.get("type") == "tool_call"]


def test_the_consent_gate_withholds_the_reader_where_the_line_is_built(case):
    root, log = case
    import tools.tool_capabilities as T
    fake = [("images_describe", {"properties": {"image_path": {"type": "string"}}}, "x",
             {"reads": ["image/*"], "case_switch": "model_vision"}),
            ("steg_steg_extract", {"properties": {"image_path": {"type": "string"}}}, "x", {"reads": ["image/jpeg"]})]
    assert T.consent_withheld(fake, root) == set()                               # the brief says on
    (root / "CASE.md").write_text("# Case\n\n| Vision descriptions | off |\n", encoding="utf-8")
    assert T.consent_withheld(fake, root) == {"images.describe"}
    assert T.consent_withheld(fake, None) == set()
    assert T.consent_withheld([("x_y", {}, "x", {"case_switch": "no_such_switch"})], root) == {"x.y"}   # unknown: off
    from core import coverage_ledger as cl
    with patch.object(T, "registered_tool_schemas", lambda: fake), patch.object(T, "_not_installed", lambda: set()):
        tools, table, gone, meta = cl._reader_context(root)
        assert "images.describe" in gone and table["image/*"] == ["images.describe"]
        # Withheld by consent: no reader of the leave at all, so an
        # image class may still leave on the other readers' failures.
        assert cl._LeaveFacts(root, set()).readers_of("image/png") == []


def test_consent_is_applied_at_the_root_so_every_reader_list_and_the_manifest_follow(case, monkeypatch):
    root, log = case
    import tools.tool_capabilities as T
    fake = [("images_describe", {"properties": {"image_path": {"type": "string"}}}, "x",
             {"reads": ["image/*"], "case_switch": "model_vision"})]
    # The marks read the registry already built (never forcing it: the
    # server imports this module while it registers), so the cache is set.
    monkeypatch.setattr(T, "_REGISTERED", fake)
    monkeypatch.setattr(T, "registered_tool_schemas", lambda: fake)
    monkeypatch.setattr(T, "missing_binaries", lambda: [])
    monkeypatch.setattr(T, "missing_modules", lambda: [])
    monkeypatch.setattr(T, "missing_probed", lambda: [])
    assert "images.describe" not in T._not_installed() and "images.describe" not in T.unavailable_tools()
    (root / "CASE.md").write_text("# Case\n\n| Vision descriptions | off |\n", encoding="utf-8")
    assert "images.describe" in T._not_installed()
    assert T.unavailable_tools()["images.describe"].startswith("withheld for this case")
    assert not T.is_installed("images.describe", T._not_installed())


def test_the_bomb_warning_is_an_error_in_the_decoder(tmp_path, monkeypatch):
    """Between Pillow's bomb ceiling and twice it Pillow only warns and
    decodes the whole picture; the child treats the warning as an error."""
    from PIL import Image
    from tools import images_decode as D
    src = _picture(tmp_path / "a.jpg", size=(64, 48))
    out = str(tmp_path / "o.img")
    monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", 2000)               # 64 x 48 = 3072: warn, not raise
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = D.main(["x", src, out, str(I.MAX_PIXELS)])
    assert code == 2 and "DecompressionBomb" in json.loads(buf.getvalue().strip().splitlines()[-1])["error"]
    monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", 89_478_485)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        assert D.main(["x", src, out, str(I.MAX_PIXELS)]) == 0 and json.loads(buf.getvalue().strip())["ok"] is True
