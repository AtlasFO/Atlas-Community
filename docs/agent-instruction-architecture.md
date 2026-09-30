# Agent instruction architecture

Modular `hub/playbook/` + thin `hub/ENTRY.md` entrypoint. Behaviour is
assembled in-process by `bin/atlas` / `agent.prompts`; browsing the playbook
directory is optional.

## Layout

```text
hub/
  ENTRY.md                  # thin entry (role, priorities, index)
  playbook/
    MANIFEST                # ordered module list
    01_….md … 17_….md       # modular instructions
  playbook.assembled.md     # optional debug artifact (gitignored)
```

Case briefs live at `cases/<CASE_ID>/CASE.md` (legacy `CLAUDE.md` still accepted).

## Assembly

| Consumer | How |
|----------|-----|
| `bin/atlas` | `agent.prompts` → `agent.playbook.assemble_playbook()` |
| `install.sh` | Smoke-checks assembly (`python -m agent.playbook`) |
| CLI | `python -m agent.playbook` / `-o PATH` |

Edit modules under `hub/playbook/` — not a monolith. Order comes from
`MANIFEST`. Modules are organization only; they must not change investigative
behaviour relative to the former single file.

## Classification

| Kind | Example | Change process |
|------|---------|----------------|
| Product behaviour | reporting preference, claim promotion | playbook module + tests |
| Code-enforced | gates, MCP routing | `tools/_gates/*` — prompts must not contradict |

Do not duplicate gate logic in prompts; if code and prompt disagree, **code wins**.

## Verify

```bash
pytest tests/agent/test_playbook.py -q --no-cov
python -m agent.playbook -o /tmp/atlas-playbook.md
```
