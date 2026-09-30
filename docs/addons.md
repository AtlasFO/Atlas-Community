# Writing Atlas addons

Atlas's forensic tool surface (`img.*`, `tsk.*`, `vol.*`, ...) is all core
code. Anything you'd add on top — a new integration, a customer-specific
parser, a hook that watches every tool call — is an **addon**, living under
`plugins/<name>/`. This is the one supported way to extend Atlas without
touching core.

One addon ships with Atlas and doubles as a worked example:

- **`plugins/timeline_builder/`** — the `@hook()` example. Observes every
  tool call to build the case timeline.

There's no shipped `@tool()` example addon today — every forensic
integration Atlas ships (Volatility, Sleuth Kit, EZ Tools, Hayabusa, ...) is
a permanent part of the product and lives as a plain `tools/*.py` module
instead (see "Addon vs. core tool" below). The inline `MyAddon` example in
the next section is the reference for `@tool()` until a real one ships.

## The SDK

```python
from core.addons import Addon, tool, hook

class MyAddon(Addon):
    name = "my_addon"

    @tool()
    def hello(self, name: str) -> dict:
        """One-line docstring becomes the tool's MCP description."""
        return {"greeting": f"Hello {name}"}

    @hook()
    def after_every_call(self, tool_name: str, args: dict, result) -> None:
        """Runs after every MCP tool call, fail-open."""
        ...

def register(mcp) -> None:
    MyAddon().register(mcp)
```

That's the whole surface: subclass `Addon`, set `name`, decorate methods,
define a module-level `register(mcp)`. `Addon.register()` (inherited, not
overridden) does the rest.

`core.addons` is a thin, friendlier layer over the `mcp.mount()` /
`mcp.add_middleware()` calls every addon already had to make by hand — it is
**not a new runtime**. Addons still register through the one stable
integration point (`core.plugins.register_plugins()` → `server.py`); the SDK
only makes the *authoring* side easier.

### `@tool()` — expose a new forensic tool

```python
@tool(name=None, description=None)
def method(self, ...) -> dict: ...
```

- Mounted under `mcp.mount(sub, namespace=self.name)`, so a method named
  `hello` on an addon named `my_addon` becomes callable as `my_addon.hello`.
- Type hints on the parameters become the tool's schema — exactly like a
  plain FastMCP `@mcp.tool()` function. `self` is dropped automatically.
- The docstring becomes the tool's MCP description unless you pass
  `description=` explicitly.
- Stack `@output_safe` (from `core.paths`) below `@tool()` if the method
  takes an `output_dir`/`output_path`/`storage_file` argument — same
  convention as core tools:

  ```python
  from core import output_safe

  @tool()
  @output_safe
  def triage(self, evtx_path: str, output_dir: str) -> dict: ...
  ```

### `@hook()` — observe every tool call

```python
@hook(event="after_tool_call")
def method(self, tool_name: str, args: dict, result) -> None: ...
```

- Called after **every** MCP tool call completes, with the tool's dotted
  name, its arguments, and its result. This is one of the events in
  `core.addons.EVENTS` — see *Events* below for the others and for the rule
  that keeps them apart.
- The return value is ignored, and the SDK catches and logs any exception
  your hook raises — it can never break the investigation that triggered
  it. Still, wrap risky bodies in your own `try/except` so you control the
  warning message (see `timeline_builder`'s `capture()` for the pattern).
- One `Addon` can define multiple `@hook()` methods; all run in declaration
  order after each call.

### Events — where core calls your addon

An event is a moment in a run that core owns and addons may react to. The
vocabulary lives in one place, `core.addons.EVENTS`, and `@hook()` refuses a
name that is not in it, so a typo fails at import instead of never firing.

| Event | Signature | Dispatched when |
|---|---|---|
| `after_tool_call` | `(tool_name: str, args: dict, result)` | every MCP tool call completes |
| `report_finalized` | `(case_dir: str, report_path: str) -> dict` | a final report has been written, by any writer |

```python
from core.addons import REPORT_FINALIZED, Addon, hook

class MyAddon(Addon):
    name = "my_addon"

    @hook(REPORT_FINALIZED)
    def finalize(self, case_dir: str, report_path: str) -> dict:
        return {"success": True, "path": ...}   # reaches the caller's record
```

Two properties matter more than the list itself:

- **Only `after_tool_call` rides the tool-call path.** Every other event is
  dispatched by the core code that owns the moment, through
  `core.plugins.dispatch_event(event, **payload)`. A hook for one event is
  never handed another event's arguments.
- **Off means off, and off is visible.** `dispatch_event` skips a disabled
  addon and returns `{"addon": ..., "status": "disabled"}` for it, alongside
  `ok` (with your return value) and `failed` (with the error). Callers that
  need to explain an absent artifact ask `core.plugins.addons_for_event()`,
  which reports who would produce it and whether they are switched on. An
  optional addon may be absent; it is never silently absent.

**Adding an event** (the extension point this is a seed for): name it in
`core/addons/sdk.py`'s `EVENTS`, dispatch it from the single place in core
that owns that moment, document its signature in the table above, and give
it a test that a disabled addon is reported rather than skipped. Nothing
else in core should learn an addon's name — if it has to, the event is
wrong.

### `@intel_reader()` — read your own indicator format

An organisation that exports indicators in a format of its own adds a
reader instead of converting files by hand: a method marked
`@intel_reader("name", suffixes=(".ext",))` that takes a path and yields
rows (dicts with at least `value`). `atlas intel add` and command sources
then use it like a built-in reader. The row fields and the rules every row
passes are in `docs/intel.md`.

### Fail-open is not optional

Every addon must degrade to "unavailable" cleanly rather than raising into
the investigation. If your addon wraps an external binary that might not be
provisioned, check for it up front and return a specific, actionable
message instead of letting the call raise:

```python
_UNAVAILABLE_HINT = "my-binary not found. Install it with ... or set MY_ADDON_HOME."

@tool()
def run(self, ...) -> dict:
    if _binary() is None:
        return {"success": False, "error": _UNAVAILABLE_HINT}
    ...
```

`tools/hayabusa.py` (a core tool, not an addon, but the same convention
applies) is a good reference for this pattern end to end: binary/rule
resolution, a `status` tool that reports install health, and a real
external-tool call that stays fail-open.

## Addon vs. core tool

Not every new integration should be an addon. The dividing line:

- **Addon** (`plugins/<name>/`, this SDK) — something optional, deployment-
  or customer-specific, that a given install might not want: a bespoke
  parser for one customer's log format, a hook that ships data to an
  external system, an experimental integration not everyone needs.
  Disableable per-install via `ATLAS_PLUGINS_DISABLED`, discovered
  automatically, no `server.py` change required to add or remove one.
- **Core tool** (`tools/<name>.py`, plain `@mcp.tool()` functions on a
  module-level `mcp = FastMCP("name")`, wired into `server.py` next to
  `tools.plaso`/`tools.volatility`/etc.) — a permanent part of what Atlas
  is. Every investigation can call it; it isn't something an install would
  reasonably want to switch off.

`tools/hayabusa.py` is a core tool for exactly this reason: Sigma triage of
Windows event logs is a first-class Atlas capability every investigation
can reach, not an optional extra — Windows/DFIR is the whole point of the
product. Wrapping an external binary doesn't make something an addon by itself;
what makes something an addon is that not every install needs it.

If you're unsure which one you're writing: would a customer ever want to
turn this off, or does it vary by deployment? Addon. Is it just "one more
forensic tool Atlas knows how to run"? Core tool — skip this SDK, copy the
shape of an existing `tools/*.py` module instead (`@mcp.tool()` decorated
functions, no `Addon` subclass, `mcp = FastMCP("name")` mounted directly in
`server.py`).

## `addon.yaml` (optional metadata)

Drop this next to `plugin.py` to participate in `atlas addon list`:

```yaml
name: my_addon
version: "1.0.0"
description: One line describing what this addon does.
author: Your Name
min_atlas_version: "1.0.0"
```

All fields are optional and metadata-only — nothing in the loader requires
a manifest, and a missing/malformed one never blocks the addon from
registering (`core.plugins.read_manifest()` fails open). `min_atlas_version`
is **warn-only**: a version mismatch shows up in `atlas addon list` but the
addon is still loaded and attempted.

## Adding a new addon — checklist

1. `mkdir plugins/my_addon`, add `__init__.py` re-exporting `register`:
   ```python
   from plugins.my_addon.plugin import register
   __all__ = ["register"]
   ```
2. Write `plugin.py`: subclass `Addon`, decorate methods with `@tool()` and
   `@hook(<event>)` (see *Events* above), define `register(mcp)`.
3. (Optional) add `addon.yaml`.
4. Discovery is automatic — `core/plugins.py` walks `plugins/` via
   `pkgutil.iter_modules` and imports anything exposing `register`. Restart
   the MCP server and your tools/hooks are live.
5. `atlas addon list` shows it; `ATLAS_PLUGINS_DISABLED=my_addon` disables
   it without removing the code.

## Scaffolding a new addon from the CLI

```
atlas addon create my_addon
```

Generates `plugins/my_addon/{__init__.py,plugin.py,addon.yaml}` from the
template above, with `name` already filled in. Edit `plugin.py` to add real
`@tool()`/`@hook()` methods.

```
atlas addon list
```

Lists every discovered addon with its enabled/compatible state, version,
and description — the CLI-facing view of `core.plugins.list_addons()`.

## Why not Lua / an out-of-process protocol?

Considered and rejected for the first version of this SDK:

- **Lua sandbox** — would let addon authors write in a language with no
  access to Atlas's own Python helpers (`core.paths`, `core.run`,
  evidence-safety checks), meaning every addon reimplements safety checks
  Atlas already has, in a different language. Not worth it for a codebase
  that is Python end-to-end and where addons need those same guarantees.
- **Out-of-process protocol** (addon as a separate process talking JSON-RPC
  or similar) — real isolation benefit, but doubles the deployment surface
  (a process to launch/monitor/restart per addon) for a product whose addons
  today are "a few Python files," not untrusted third-party code needing a
  security boundary. Revisit if Atlas ever needs to run addons it doesn't
  trust.

The in-process Python SDK above keeps the fail-open guarantees, evidence
read-only checks, and output-safety helpers exactly as available to core
tools, at the cost of addons needing to be trusted Python code — true of
every addon Atlas ships today.

## History: what this replaced

Before this SDK, each addon hand-rolled its own `mcp.mount()` /
`mcp.add_middleware()` calls and, for hooks, its own
`fastmcp.server.middleware.Middleware` subclass; the timeline builder's hook
now lives in `plugin.py`'s `@hook()` method.
