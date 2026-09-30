"""Tests for batch_run's raw-bash enumeration cap.

GLM analysts loop near-identical raw commands (the same raw fls, cat or
strings call repeated a dozen or more times) instead of pivoting to typed tools. After
_RAW_CAP_MAX near-identical commands in the trailing window batch_run
refuses with gate=raw_bash_enumeration_cap and names the typed equivalent.
"""
from unittest.mock import patch

import tools.misc as misc


def _raw_entry(cmd, source=None, mcp_tool="misc_batch_run"):
    e = {"type": "tool_call", "cmd": cmd, "success": True}
    if source:
        e["source"] = source
        e.pop("mcp_tool", None)
    if mcp_tool and not source:
        e["mcp_tool"] = mcp_tool
    return e


def _seed(entries):
    import core.execution_log as elog
    elog.log._entries.extend(entries)


class TestNormalization:
    def test_offsets_and_inodes_collapse(self):
        a = misc._normalize_raw_cmd(["fls", "-o", "63", "img.dd", "128-1"])
        b = misc._normalize_raw_cmd(["fls", "-o", "2048", "img.dd", "999"])
        assert a == b == "fls img.dd"

    def test_distinct_targets_stay_distinct(self):
        a = misc._normalize_raw_cmd(["strings", "/mnt/e/a.bin"])
        b = misc._normalize_raw_cmd(["strings", "/mnt/e/b.bin"])
        assert a != b

    def test_numbered_artifacts_are_separate_targets(self):
        """A carver numbers what it produces. Reading the files a tool has
        just written is the work, not a loop, so the numbers that tell them
        apart have to survive the signature — otherwise the cap refuses the
        batch and asks for the different file it was already given."""
        a = misc._normalize_raw_cmd(
            ["head", "-c", "200", "analysis/streams/00000003.html"])
        b = misc._normalize_raw_cmd(
            ["head", "-c", "200", "analysis/streams/00000004.html"])
        assert a != b
        assert a == "head 00000003.html"

    def test_numbered_images_are_separate_targets(self):
        a = misc._normalize_raw_cmd(["cat", "/mnt/e/usb1.dd"])
        b = misc._normalize_raw_cmd(["cat", "/mnt/e/usb2.dd"])
        assert a != b

    def test_digits_in_a_parameter_still_collapse(self):
        """``skip=`` names an offset, not a target: one file read at two
        offsets is one target."""
        a = misc._normalize_raw_cmd(["dd", "if=/mnt/e/usb.dd", "skip=63"])
        b = misc._normalize_raw_cmd(["dd", "if=/mnt/e/usb.dd", "skip=2048"])
        assert a == b

    def test_string_and_list_forms_agree(self):
        assert (misc._normalize_raw_cmd("strings -n 8 /mnt/e/a.bin")
                == misc._normalize_raw_cmd(["strings", "-n", "8",
                                            "/mnt/e/a.bin"]))


class TestEnumerationCap:
    def test_cap_refuses_after_n(self):
        _seed([_raw_entry("strings -n 8 /mnt/e/usb.dd")] * misc._RAW_CAP_MAX)
        r = misc.batch_run([{"cmd": ["strings", "-n", "12",
                                     "/mnt/e/usb.dd"]}])
        res = r["results"][0]
        assert res["success"] is False
        assert res["gate"] == "raw_bash_enumeration_cap"
        assert "strings.strings_extract" in res["redirect_to"]
        assert res["occurrences"] == misc._RAW_CAP_MAX
        # top-level gate so the middleware baseline classifies gate_refusal
        assert r["gate"] == "raw_bash_enumeration_cap"

    def test_force_does_not_bypass_cap(self):
        _seed([_raw_entry("strings /mnt/e/usb.dd")] * misc._RAW_CAP_MAX)
        r = misc.batch_run([{"cmd": ["strings", "/mnt/e/usb.dd"],
                             "force": True}])
        assert r["results"][0]["success"] is False
        assert r["results"][0]["gate"] == "raw_bash_enumeration_cap"

    def test_below_threshold_runs(self):
        _seed([_raw_entry("strings /mnt/e/usb.dd")]
              * (misc._RAW_CAP_MAX - 1))
        with patch("tools.misc.run", return_value={"success": True}) as m:
            r = misc.batch_run([{"cmd": ["strings", "/mnt/e/usb.dd"]}])
        assert m.called
        assert r["results"][0]["success"] is True

    def test_distinct_targets_pass(self):
        _seed([_raw_entry(f"strings /mnt/e/file-a{i}b.bin")
               for i in range(misc._RAW_CAP_MAX + 2)])
        with patch("tools.misc.run", return_value={"success": True}) as m:
            r = misc.batch_run([{"cmd": ["strings", "/mnt/e/fresh.bin"]}])
        assert m.called
        assert r["results"][0]["success"] is True

    def test_window_expiry_forgives_old_loop(self):
        old = [_raw_entry("strings /mnt/e/usb.dd")] * misc._RAW_CAP_MAX
        recent = [_raw_entry(f"7z x arc-part{i}.zip")
                  for i in range(misc._RAW_CAP_WINDOW)]
        _seed(old + recent)
        with patch("tools.misc.run", return_value={"success": True}) as m:
            r = misc.batch_run([{"cmd": ["strings", "/mnt/e/usb.dd"]}])
        assert m.called
        assert r["results"][0]["success"] is True

    def test_claude_code_bash_entries_count(self):
        _seed([_raw_entry("cat /mnt/e/pagefile.sys",
                          source="claude_code_bash")] * misc._RAW_CAP_MAX)
        r = misc.batch_run([{"cmd": ["cat", "/mnt/e/pagefile.sys"]}])
        assert r["results"][0]["success"] is False
        assert r["results"][0]["gate"] == "raw_bash_enumeration_cap"

    def test_typed_tool_subprocess_entries_do_not_count(self):
        # entries without mcp_tool=misc_batch_run/source=claude_code_bash are
        # typed tools' internal subprocesses; they must not feed the counter
        _seed([{"type": "tool_call", "cmd": "strings /mnt/e/usb.dd",
                "success": True, "mcp_tool": "strings_strings_extract"}]
              * (misc._RAW_CAP_MAX + 2))
        with patch("tools.misc.run", return_value={"success": True}) as m:
            r = misc.batch_run([{"cmd": ["strings", "/mnt/e/usb.dd"]}])
        assert m.called
        assert r["results"][0]["success"] is True

    def test_mixed_batch_caps_only_looping_spec(self):
        _seed([_raw_entry("strings /mnt/e/usb.dd")] * misc._RAW_CAP_MAX)
        with patch("tools.misc.run", return_value={"success": True}) as m:
            r = misc.batch_run([{"cmd": ["strings", "/mnt/e/usb.dd"]},
                                {"cmd": ["7z", "x", "fresh.zip"]}])
        assert r["results"][0]["gate"] == "raw_bash_enumeration_cap"
        assert r["results"][1]["success"] is True
        assert m.call_count == 1

    def test_fail_open_on_broken_log(self):
        with patch("tools.misc._normalize_raw_cmd",
                   side_effect=RuntimeError("boom")), \
             patch("tools.misc.run", return_value={"success": True}) as m:
            r = misc.batch_run([{"cmd": ["strings", "/mnt/e/usb.dd"]}])
        assert m.called
        assert r["results"][0]["success"] is True


class TestRefusalClassification:
    def test_cap_refusal_payload_classifies_gate_refusal(self):
        from core.middleware import _app_level_failure
        _seed([_raw_entry("strings /mnt/e/usb.dd")] * misc._RAW_CAP_MAX)
        r = misc.batch_run([{"cmd": ["strings", "/mnt/e/usb.dd"]}])
        failure = _app_level_failure(r)
        assert failure is not None
        assert failure[1] == "gate_refusal"
        assert "raw_bash_enumeration_cap" in failure[0]


class TestRawToolHint:
    def test_hard_wrapper_hint_wins(self):
        from core.middleware import raw_tool_hint
        assert "tsk.tsk_fls" in raw_tool_hint("fls")

    def test_soft_hint_for_capped_binaries(self):
        from core.middleware import raw_tool_hint
        assert "strings.strings_grep" in raw_tool_hint("grep")
        assert "tsk.tsk_icat" in raw_tool_hint("cat")
        assert "hash.hash_file" in raw_tool_hint("sha256sum")

    def test_generic_fallback(self):
        from core.middleware import raw_tool_hint
        assert "typed tool namespace" in raw_tool_hint("awk")
