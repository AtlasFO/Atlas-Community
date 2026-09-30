# Coding guidelines (when editing Atlas itself)

These instructions are for **investigations**. When changing Atlas source code:

- Prefer evolution over redesign; keep Phases 1–7 contracts stable.
- Do not weaken gates to make a run "pass".
- Case briefs (`cases/*/CASE.md`) are the investigator **work inbox**
  (Investigation Requests only) — not investigation state, findings, or memory.
  Durable state lives under `.atlas/` (tasks, plan, claim graph).
- Playbook modules live under `hub/playbook/`; assemble via
  `python -m agent.playbook` (used by `bin/atlas` and `install.sh`).
