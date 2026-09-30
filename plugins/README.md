# Atlas Investigation Plugins (Addons)

Addons extend Atlas investigations without modifying the core pipeline. Each
addon lives under `plugins/<name>/` and registers through a single stable
integration point in `server.py`:

```python
from core.plugins import register_plugins
register_plugins(mcp)
```

## Writing an addon

Full authoring guide with worked examples: **`docs/addons.md`**. Short
version — subclass `core.addons.Addon` and decorate methods:

```python
# plugins/my_addon/plugin.py
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

`@tool()` methods are mounted under `mcp.mount(..., namespace=self.name)`, so
`hello` above becomes callable as `my_addon.hello`. `@hook()` methods are
attached as FastMCP middleware, called after each tool call completes. Both
decorators are thin wrappers over the `mount()`/`add_middleware()` calls
every addon already had to make by hand — this is not a new runtime, just a
friendlier authoring layer over the same one.

Steps to add a new addon:

1. Create `plugins/my_addon/` with `__init__.py`, `plugin.py`, and (optional
   but recommended) `addon.yaml` — see below.
2. Subclass `Addon`, decorate tool/hook methods, define `register(mcp)`.
3. Restart the MCP server. Discovery is automatic (`core/plugins.py`).

Addons must be **fail-open**: errors must never break investigations. Wrap
hook bodies in `try/except` and log a warning rather than raising.

### `addon.yaml` (optional metadata)

```yaml
name: my_addon
version: "1.0.0"
description: One line describing what this addon does.
author: Your Name
min_atlas_version: "0.9.8"
```

Read via `core.plugins.read_manifest(name)`; backs `atlas addon list`.
Compatibility checking (`min_atlas_version`) is warn-only — a mismatch never
blocks loading, it only surfaces in `atlas addon list`.

## Environment

| Variable | Effect |
|----------|--------|
| `ATLAS_PLUGINS=0` | Disable all addons |
| `ATLAS_PLUGINS_DISABLED=timeline_builder,...` | Disable named addons |
| `ATLAS_TIMELINE_LLM=1` | LLM-enrich timeline Event/Description fields |

Not every new integration belongs here — see "Addon vs. core tool" in
`docs/addons.md`. Sigma triage of Windows event logs (Hayabusa), for
example, is a permanent core capability and lives as a plain tool module at
`tools/hayabusa.py`, mounted in `server.py` like `tools/plaso.py` — not an
addon, because no install would reasonably want to switch it off.

## Timeline Builder (`plugins/timeline_builder/`)

Collects forensic events during investigations and writes one **curated**
`reports/master_timeline.tsv` when a final report lands — through the
`report_finalized` event, so it runs whichever writer produced the report,
and not at all when the addon is switched off (Settings → Plugins). Curation is
**narrative-scored** (Claim Graph entities + asserted evidence classes +
multi-producer coverage), not a hardcoded event-type allow/deny list.
Auth/process storms are aggregated into summary rows (users listed in the
description). Raw capture stays under `.timeline_build/` for search. This is
also the SDK's worked `@hook()` example — see `docs/addons.md`.

### Architecture

```
Readers → Mapper → Builder → Collapse → Aggregate storms → Narrative curate → Export
                              ↘ LLM enrich (optional, prose only)
```

- **Readers** parse tool output into `EvidenceRecord` rows.
- **Mapper** converts records into `NormalizedTimelineEvent` objects.
- **Builder** merges, sorts, deduplicates — no tool-specific knowledge.
- **Collapse** compresses repetitive chains (first / samples / summary / last).
- **Curate** keeps findings + Claim Graph principals (users/IPs/MACs/serials);
  drops unmatched farm noise once claims exist.
- **LLM** rewrites title/description only; never invents facts.

The **Source** column always names the original forensic artifact (for example
`Windows Security Event Log (Event ID 4688)`), never parser or tool names.

### Per-case configuration

Copy filter rules to `<case>/timeline_config.yaml` to override defaults in
`plugins/timeline_builder/config.yaml`.

### Output

- Staging (raw capture): `reports/.timeline_build/events.jsonl`
- Deliverable (curated): `reports/master_timeline.tsv`
- Report hook: `@hook(REPORT_FINALIZED)` on the addon writes the TSV after any final report; the report's appendix names the file when present and says why when it is absent
