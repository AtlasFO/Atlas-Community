"""Tests for agent/toolbox.py against a small fixture FastMCP server."""
import json

import pytest
from fastmcp import FastMCP

import agent.toolbox as toolbox_mod
from agent.toolbox import Toolbox, _truncate


@pytest.fixture()
def tb(monkeypatch):
    inner = FastMCP("vol")

    @inner.tool
    def vol_pslist(memory_image: str) -> dict:
        """List processes."""
        return {"success": True, "image": memory_image}

    misc = FastMCP("misc")

    @misc.tool
    def record_finding(title: str) -> dict:
        """Record a finding."""
        return {"success": True, "title": title}

    root = FastMCP("fixture")
    root.mount(inner, namespace="vol")
    root.mount(misc, namespace="misc")

    class FakeServer:
        mcp = root

    monkeypatch.setitem(__import__("sys").modules, "server", FakeServer)
    return Toolbox(loaded=("misc",))


class TestDiscovery:
    def test_names_and_namespaces(self, tb):
        assert set(tb.tools) == {"vol_vol_pslist", "misc_record_finding"}
        assert tb.namespaces == ["misc", "vol"]
        assert tb.loaded == {"misc"}

    def test_alias_resolution_both_forms(self, tb):
        assert tb.resolve("vol.pslist") == "vol_vol_pslist"
        assert tb.resolve("vol.vol_pslist") == "vol_vol_pslist"
        assert tb.resolve("misc.record_finding") == "misc_record_finding"
        assert tb.resolve("vol_vol_pslist") == "vol_vol_pslist"
        assert tb.resolve("nope.tool") is None

    def test_openai_schemas_only_loaded_namespaces(self, tb):
        names = [t["function"]["name"] for t in tb.openai_tools()]
        assert "misc_record_finding" in names
        assert "vol_vol_pslist" not in names
        assert "atlas_load_namespaces" in names  # meta-tools always present


class TestExecution:
    def test_call_and_render(self, tb):
        out, auto = tb.call("misc.record_finding", {"title": "t1"})
        assert not auto
        assert json.loads(out)["title"] == "t1"

    def test_autoload_on_unloaded_namespace(self, tb):
        out, auto = tb.call("vol.pslist", {"memory_image": "m.img"})
        assert auto
        assert "vol" in tb.loaded
        assert json.loads(out)["image"] == "m.img"

    def test_unknown_tool_is_error_string(self, tb):
        out, _ = tb.call("bogus", {})
        assert out.startswith("ERROR: unknown tool")

    def test_a_call_written_as_call_syntax_into_the_name_is_recovered(self, tb):
        """A model may write the whole call into the name field, with the
        tag of whatever template it was closing. The bare name resolves and
        the literal keyword values are the arguments."""
        name = 'misc.record_finding(title="t1")</arg_value>'
        assert tb.resolve(name) == tb.resolve("misc.record_finding")
        assert tb.listed_name(name) == tb.listed_name("misc.record_finding")
        out, _ = tb.call(name, {})
        assert json.loads(out)["title"] == "t1"
        # Arguments the call carried in their own field win over the name.
        out, _ = tb.call(name, {"title": "t2"})
        assert json.loads(out)["title"] == "t2"

    def test_call_syntax_on_an_unknown_name_is_still_unknown(self, tb):
        out, _ = tb.call('bogus(x=1)', {})
        assert out.startswith("ERROR: unknown tool")

    def test_malformed_arguments_reported(self, tb):
        out, _ = tb.call("misc.record_finding",
                         {"_malformed_arguments": "{oops"})
        assert "not valid JSON" in out


class TestToolBudget:
    def test_refuse_load_over_limit(self, tb, monkeypatch):
        # 4 meta + 1 misc tool = 5; loading vol (+1) would be 6
        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 5)
        assert tb.schema_count() == 5
        result = tb.load_with_budget(["vol"])
        assert result["newly_loaded"] == []
        assert result["refused"] and result["refused"][0]["namespace"] == "vol"
        assert "vol" not in tb.loaded
        assert tb.schema_count() == 5

    def test_autoload_refuses_over_limit(self, tb, monkeypatch):
        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 5)
        out, auto = tb.call("vol.pslist", {"memory_image": "m.img"})
        assert auto is False
        assert "tool-budget" in out
        assert "vol" not in tb.loaded

    def test_a_refused_autoload_names_what_holds_the_budget(self, monkeypatch):
        """Eviction spares a namespace used in the last few calls, so the
        refusal must say which loaded namespace holds the room and the one
        unload that frees it; a run left to work that out gave up a
        correlation instead. (The shared fixture's misc tool is control
        plane and frees nothing, so this one builds a holder of its own.)"""
        tsk = FastMCP("tsk")

        @tsk.tool
        def tsk_fls(image: str) -> dict:
            return {"success": True}

        @tsk.tool
        def tsk_icat(image: str) -> dict:
            return {"success": True}

        @tsk.tool
        def tsk_mmls(image: str) -> dict:
            return {"success": True}

        vol = FastMCP("vol")

        @vol.tool
        def vol_pslist(memory_image: str) -> dict:
            return {"success": True}

        root = FastMCP("fixture")
        root.mount(tsk, namespace="tsk")
        root.mount(vol, namespace="vol")

        class FakeServer:
            mcp = root

        monkeypatch.setitem(__import__("sys").modules, "server", FakeServer)
        box = Toolbox(loaded=("tsk",))
        # 4 meta + 3 tsk = 7; vol (+1) would be 8, and tsk was just used.
        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 7)
        box.call("tsk.fls", {"image": "disk.raw"})
        out, auto = box.call("vol.pslist", {"memory_image": "m.img"})
        assert auto is False and "tool-budget" in out
        assert "Room is held by tsk (3 tools, last used 1 call ago)" in out
        assert "atlas_load_namespaces(namespaces=['vol'], unload=['tsk'])" in out
        assert "vol" not in box.loaded
        # The explicit load the model reaches for next says the same: a
        # run that asked for a namespace by name and was refused twice
        # found the holder only by reading the loaded list itself.
        pytest.importorskip("rich")
        from agent.loop import Agent
        from agent.tui import UI
        agent = Agent(client=None, toolbox=box, case_dir=None,
                      ui=UI(quiet=True), interactive=False)
        text = agent._handle_meta("atlas_load_namespaces", {"namespaces": ["vol"]})
        assert "REFUSED (tool-budget)" in text
        assert "Room is held by tsk (3 tools" in text
        assert "unload=['tsk']" in text

    def test_load_fits_within_budget(self, tb, monkeypatch):
        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 6)
        result = tb.load_with_budget(["vol"])
        assert "vol" in result["newly_loaded"]
        assert not result["refused"]
        assert "vol" in tb.loaded

    def test_force_bypasses_budget(self, tb, monkeypatch):
        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 5)
        hits = tb.load(["vol"], force=True)
        assert hits == ["vol"]
        assert "vol" in tb.loaded



def test_truncate_keeps_head_and_tail():
    text = "A" * 9000 + "MARKER_END"
    out = _truncate(text, limit=1000)
    assert len(out) < 1500
    assert out.startswith("A")
    assert out.endswith("MARKER_END")
    assert "omitted" in out


class TestCallShapeRefusals:
    """Every refusal the toolbox returns *before* dispatching must classify
    as a call-shape refusal, and nothing a tool actually reported may.

    This is the anti-drift guard for is_call_shape_refusal: the markers live
    beside the code that writes these messages, and reword one without the
    other and this fails.
    """

    def test_unknown_tool(self, tb):
        out, _ = tb.call("bogus", {})
        assert toolbox_mod.is_call_shape_refusal(out)

    def test_unexpected_keyword_argument(self, tb):
        out, _ = tb.call("misc.record_finding", {"title": "t", "nope": 1})
        assert "unexpected keyword argument" in out
        assert toolbox_mod.is_call_shape_refusal(out)

    def test_malformed_json_arguments(self, tb):
        out, _ = tb.call("misc.record_finding",
                         {"_malformed_arguments": "{oops"})
        assert toolbox_mod.is_call_shape_refusal(out)

    def test_a_cut_argument_refusal_names_the_longest_parameter(self, tb):
        """The refusal shows the head of the text, which is where the cut
        note is not; the parameter that took most of the text is named
        after it, and the refusal still classifies as a call-shape one."""
        out, _ = tb.call("misc.record_finding", {
            "_malformed_arguments": "{\"title\": \"" + "x" * 3000,
            "_longest_argument": "title (3001 characters)"})
        assert out.endswith("Longest parameter: title (3001 characters).")
        assert toolbox_mod.is_call_shape_refusal(out)

    def test_tool_budget_refusal(self, tb, monkeypatch):
        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 5)
        out, _ = tb.call("vol.pslist", {"memory_image": "m.img"})
        assert toolbox_mod.is_call_shape_refusal(out)

    def test_a_tool_that_actually_failed_is_not_a_refusal(self):
        # The tool ran and raised, or reported its own failure: real.
        assert not toolbox_mod.is_call_shape_refusal(
            "ERROR: tool 'vol_vol_pslist' raised: MemoryError")
        assert not toolbox_mod.is_call_shape_refusal(
            "TOOL ERROR: image could not be opened")

    def test_ordinary_output_is_not_a_refusal(self, tb):
        out, _ = tb.call("misc.record_finding", {"title": "t1"})
        assert not toolbox_mod.is_call_shape_refusal(out)


class TestListedNames:
    """The tool list carries the alias with its dot replaced by an
    underscore, the form a model writes after reading the playbook; the
    MCP name with its doubled namespace is still accepted on execution."""

    def test_list_carries_the_single_prefix_form(self, tb, monkeypatch):
        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 8)
        tb.load_with_budget(["vol"])
        names = [t["function"]["name"] for t in tb.openai_tools()]
        assert "vol_pslist" in names and "vol_vol_pslist" not in names
        assert "misc_record_finding" in names

    def test_every_form_resolves_and_executes(self, tb, monkeypatch):
        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 8)
        tb.load_with_budget(["vol"])
        for form in ("vol_pslist", "vol.pslist", "vol_vol_pslist"):
            assert tb.resolve(form) == "vol_vol_pslist"
            assert tb.listed_name(form) == "vol_pslist"
            out, _ = tb.call(form, {"memory_image": "m.img"})
            assert '"success": true' in out
        assert tb.listed_name("no_such_tool") is None


class TestLearnedToolCeiling:
    """Function calling degrades past a schema count that differs by model,
    so the count is learned: the loop cuts the list when a large one came
    back without a call, and the ceiling caps every later pack."""

    def test_shrink_evicts_coldest_first_and_stops_at_the_control_plane(self, tb, monkeypatch):
        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 6)
        tb.load_with_budget(["vol"])
        assert tb.schema_count() == 6
        assert tb.shrink_to(5) == ["vol"]
        assert tb.loaded == {"misc"} and tb.schema_count() == 5
        # misc's only tool is control plane, so evicting it would change
        # nothing: the floor is the meta tools plus the control tools.
        assert tb.shrink_to(1) == []
        assert tb.loaded == {"misc"} and tb.schema_count() == 5

    @staticmethod
    def _mount(monkeypatch, **sizes):
        """A server with one namespace per keyword, holding that many tools."""
        root = FastMCP("fixture")
        for ns, count in sizes.items():
            sub = FastMCP(ns)
            for i in range(count):
                def _tool(x: str, _i=i) -> dict:
                    """Fixture tool."""
                    return {"i": _i}
                sub.tool(name=f"t{i}")(_tool)
            root.mount(sub, namespace=ns)

        class FakeServer:
            mcp = root

        monkeypatch.setitem(__import__("sys").modules, "server", FakeServer)

    def test_a_cut_takes_the_largest_of_equally_cold_namespaces_first(self, monkeypatch):
        """Nothing has been used yet when a first-turn cut lands, so among
        equally cold namespaces the cut takes the largest: the fewest
        namespaces leave the list for the size asked."""
        self._mount(monkeypatch, a=1, b=2)
        tb = Toolbox(loaded=("a", "b"))
        assert tb.shrink_to(tb.schema_count() - 1) == ["b"]
        assert tb.loaded == {"a"}

    def test_a_load_may_test_one_namespace_past_a_learned_ceiling(self, monkeypatch):
        """A learned ceiling is a hypothesis. When the loop allows it, a
        load that would be refused at the ceiling goes one namespace past
        it and reports the size under test; the ceiling moves with it so
        the list is packed to that size until the reply decides. One
        namespace per load: a failure then names one size."""
        self._mount(monkeypatch, a=6, b=1, c=1)
        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 128)
        tb = Toolbox(loaded=("a",))
        ceiling = tb.schema_count()
        monkeypatch.setattr(toolbox_mod, "_LEARNED_CEILING", ceiling)
        refused = tb.load_with_budget(["b"])
        assert refused["refused"] and refused["probed"] is None
        tb.tool_probe_limit = ceiling + 2
        result = tb.load_with_budget(["b", "c"])
        assert result["probed"] == {"namespace": "b", "count": ceiling + 1, "floor": ceiling}
        assert result["newly_loaded"] == ["b"]
        assert [r["namespace"] for r in result["refused"]] == ["c"]
        assert toolbox_mod.max_openai_tools() == ceiling + 1
        # The probe waits to be read once; until then no second one is made.
        tb.tool_probe_limit = ceiling + 3
        assert tb.load_with_budget(["c"])["probed"] is None
        assert tb.pop_last_probe() == {"namespace": "b", "count": ceiling + 1, "floor": ceiling}
        assert tb.pop_last_probe() is None
        assert tb.load_with_budget(["c"])["probed"] == {"namespace": "c", "count": ceiling + 2,
                                                         "floor": ceiling + 1}

    def test_the_configured_maximum_is_never_tested(self, monkeypatch):
        """The operator's maximum and the provider window bound every test:
        a load past them is refused however far the loop would go."""
        self._mount(monkeypatch, a=6, b=1)
        tb = Toolbox(loaded=("a",))
        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", tb.schema_count())
        monkeypatch.setattr(toolbox_mod, "_LEARNED_CEILING", None)
        tb.tool_probe_limit = tb.schema_count() + 1
        result = tb.load_with_budget(["b"])
        assert result["refused"] and result["probed"] is None
        assert "b" not in tb.loaded


class TestControlPlane:
    """The control plane is listed whatever is loaded and whatever the
    budget, so a small model still gets a run that can start and close."""

    # Each test takes ``tb`` for its server patch and builds its own toolbox.

    def test_control_tools_are_listed_with_nothing_loaded(self, tb):
        tb = Toolbox(loaded=())
        names = [t["function"]["name"] for t in tb.openai_tools()]
        assert "misc_record_finding" in names and tb.loaded == set()
        assert tb.schema_count() == len(toolbox_mod.META_TOOLS) + 1
        assert tb.control_names == {"misc_record_finding"}

    def test_a_budget_below_the_control_plane_still_lists_it(self, tb, monkeypatch):
        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 2)
        tb = Toolbox(loaded=("vol",))
        names = [t["function"]["name"] for t in tb.openai_tools()]
        assert "misc_record_finding" in names and "vol" not in tb.loaded
        assert tb.pop_schema_overflow_warning() is None

    def test_calling_a_control_tool_does_not_load_its_namespace(self, tb):
        tb = Toolbox(loaded=())
        out, auto = tb.call("misc.record_finding", {"title": "t1"})
        assert '"success": true' in out and auto is False
        assert tb.loaded == set()

    def test_room_comes_from_cold_unkept_namespaces_only(self, tb, monkeypatch):
        """A cold core namespace is ordinary room now that the control plane
        is listed on its own; a kept one and one in recent use never are."""
        tb._use_clock = 50
        tb._last_used = {"misc": 3}          # cold
        assert tb._eviction_order({"misc"}, keep=set()) == ["misc"]
        assert tb._eviction_order({"misc"}, keep={"misc"}) == []
        tb._last_used = {"misc": 49}         # in recent use
        assert tb._eviction_order({"misc"}, keep=set()) == []

    def test_a_namespace_the_evidence_asked_for_outlasts_one_loaded_on_demand(self, tb):
        """Among cold namespaces, the profile's own leave last, whatever
        their recency: the disk toolkit of a disk case is not the room a
        one-off namespace makes."""
        tb._use_clock = 50
        tb.preferred = {"vol"}
        tb._last_used = {"vol": 1, "misc": 5}        # vol is colder
        assert tb._eviction_order({"vol", "misc"}, keep=set()) == ["misc", "vol"]
        tb.preferred = set()
        assert tb._eviction_order({"vol", "misc"}, keep=set()) == ["vol", "misc"]

    def test_the_preferred_set_is_what_the_case_asked_for(self, tb):
        tb2 = Toolbox(loaded=("vol", "nosuchnamespace"))
        assert tb2.preferred == {"vol"}

    def test_a_victim_that_frees_nothing_is_not_unloaded(self, tb, monkeypatch):
        """The fixture's misc holds only a control tool: unloading it would
        change the count by nothing, so a refused load leaves it loaded."""
        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 5)
        tb._use_clock = 50
        result = tb.load_with_budget(["vol"])
        assert result["refused"] and result["evicted"] == []
        assert tb.loaded == {"misc"}

    def test_a_guessed_parameter_name_is_renamed_and_reported(self, tb):
        """The fixture's record_finding takes ``title``; a call that guesses
        ``finding_title`` runs under the right parameter and the result says
        so. A guess that shares no word with it (``name``) asks for
        something else and gets the refusal that lists the parameters."""
        out, _ = tb.call("misc.record_finding", {"finding_title": "t1"})
        assert '"success": true' in out and '"title": "t1"' in out
        assert "renamed to title" in out
        out, _ = tb.call("misc.record_finding", {"name": "t1"})
        assert out.startswith("ERROR: unexpected keyword argument")
        assert "Allowed parameters: title" in out
        out, _ = tb.call("misc.record_finding", {"finding_title": "t1", "extra": "x"})
        assert out.startswith("ERROR: unexpected keyword argument")

    def test_a_sibling_whose_signature_the_arguments_fit_is_named_not_called(self, monkeypatch):
        """Arguments that all belong to exactly one other tool of the same
        namespace are that tool's signature under the wrong name: the
        refusal names the tool and runs nothing. Arguments two siblings
        would both take, or none takes, get the plain refusal."""
        root, misc = FastMCP("fixture"), FastMCP("misc")
        ran = []

        @misc.tool
        def record_finding(title: str) -> dict:
            """Record a finding."""
            ran.append(("finding", title))
            return {"success": True}

        @misc.tool
        def record_note(content: str, disposition: bool = False) -> dict:
            """Record a note."""
            ran.append(("note", content))
            return {"success": True}

        @misc.tool
        def record_memo(content: str, disposition: bool = False, tag: str = "") -> dict:
            """Record a memo."""
            ran.append(("memo", content))
            return {"success": True}

        root.mount(misc, namespace="misc")

        class FakeServer:
            mcp = root

        monkeypatch.setitem(__import__("sys").modules, "server", FakeServer)
        tb = Toolbox(loaded=("misc",))
        out, _ = tb.call("misc.record_finding",
                         {"content": "no match", "disposition": True, "tag": "t"})
        assert out.startswith("ERROR: unexpected keyword argument")
        assert "signature of 'misc.record_memo'" in out and ran == []
        # Two siblings take {content, disposition}: no guess between them.
        out, _ = tb.call("misc.record_finding", {"content": "x", "disposition": True})
        assert out.startswith("ERROR: unexpected keyword argument")
        assert "signature of" not in out
        # A parameter no sibling takes fits nobody's signature.
        out, _ = tb.call("misc.record_finding", {"content": "x", "nope": 1})
        assert out.startswith("ERROR: unexpected keyword argument")
        assert "signature of" not in out

    def test_colon_separated_names_resolve_too(self, tb):
        assert tb.resolve("vol:pslist") == "vol_vol_pslist"
        assert tb.listed_name("misc:record_finding") == "misc_record_finding"

    def test_a_bare_short_name_resolves_only_when_one_tool_carries_it(self, monkeypatch):
        """A call written with the function name alone, no namespace,
        names the one tool that carries it; a short name two tools share
        stays unknown rather than guessed."""
        root = FastMCP("fixture")
        carve, vol, net = FastMCP("carve"), FastMCP("vol"), FastMCP("net")

        @carve.tool
        def foremost_carve(image: str) -> dict:
            """Carve."""
            return {"success": True, "image": image}

        @vol.tool
        def status() -> dict:
            """Status."""
            return {"success": True}

        @net.tool
        def net_status() -> dict:
            """Status."""
            return {"success": True}

        for ns, sub in (("carve", carve), ("vol", vol), ("net", net)):
            root.mount(sub, namespace=ns)

        class FakeServer:
            mcp = root

        monkeypatch.setitem(__import__("sys").modules, "server", FakeServer)
        tb = Toolbox(loaded=())
        assert tb.resolve("foremost_carve") == "carve_foremost_carve"
        assert tb.listed_name("foremost_carve") == "carve_foremost_carve"
        assert tb.resolve("foremost_carve(image='a.img')") == "carve_foremost_carve"
        out, _ = tb.call("foremost_carve", {"image": "a.img"})
        assert '"image": "a.img"' in out
        # Both vol_status and net_net_status shorten to ``status``.
        assert tb.resolve("status") is None
        assert tb.call("status", {})[0].startswith("ERROR: unknown tool")
        assert tb.resolve("vol_status") == "vol_status"
        assert tb.resolve("net.status") == "net_net_status"

    def test_the_summary_names_the_control_plane_and_the_call_form(self, tb):
        tb = Toolbox(loaded=())
        summary = tb.namespace_summary()
        assert "Always callable" in summary and "misc_record_finding" in summary
        assert "call as vol_<name>" in summary

    def test_learned_ceiling_caps_the_budget(self, monkeypatch):
        monkeypatch.setattr(toolbox_mod, "_LEARNED_CEILING", None)
        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 128)
        toolbox_mod.set_learned_tool_ceiling(40)
        assert toolbox_mod.max_openai_tools() <= 40
        toolbox_mod.set_learned_tool_ceiling(None)
        assert toolbox_mod.max_openai_tools() > 40
