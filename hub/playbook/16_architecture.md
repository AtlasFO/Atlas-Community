# Architecture notes (prompt vs code)

Atlas's investigation model lives primarily in **code**. Prompts steer the
investigator; gates and state stores enforce forensic correctness.

| Concern | Authoritative location | Prompt role |
|---------|------------------------|-------------|
| Claim Graph / conflicts / supersession | `core/claim_graph.py`, `claim.*` | Prefer promoting beliefs; never silent overwrite |
| Current Investigation State | `core/investigation_state.py`, `misc.current_investigation_state` | Snapshot before report |
| Report Projection | `core/report_projection.py`, `misc.write_projected_final_report` | Markdown is never SoT |
| Incremental rerun | `atlas rerun`, `.atlas/` | Prefer continuity over wipe |
| Finding / export gates | `tools/_gates/*`, `record_finding` | Remediate when refused — see `gates_reference.md` |
| Evidence path / MCP routing | executor + middleware | Never bypass via Bash |

Product docs: `docs/architecture-investigation.md`, `docs/investigation-state.md`.

Do **not** restate gate logic here in full — if code and prompt disagree, **code wins**.
