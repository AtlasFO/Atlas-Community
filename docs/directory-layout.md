# Directory layout — inside vs outside the repository

Atlas keeps the **application** and **bundled study data** inside the git tree.
**Customer investigations** stay outside the repository on purpose.

## Outside the repository

| Path | Role |
|------|------|
| `~/cases/` | **Production investigations** (evidence, analysis, reports). Create new cases here from `case-template/`. |
| `~/cases/.common/` | Lab-local shared config (the four MITRE tables, `live_hosts.json`). |
| `~/.cache/atlas/` | Runtime cache: session beacon, dashboard discovery, hash cache, locks, `install_report.json` (what the installer found), `mitre_refresh.json` (state of a table refresh). |
| `~/.atlas_history` | CLI chat history. |
| `~/.venv` → `Atlas/.venv` | Optional compat symlink; the real venv is in-repo. |
| `~/.local/bin/atlas*` | PATH wrappers → `Atlas/bin/`. |

## Inside the repository (`~/Atlas/`)

| Path | Role |
|------|------|
| `hub/` | Investigator playbook (`ENTRY.md` + modules) for the Hub CLI. |
| `agent/`, `tools/`, `core/`, `dashboard/`, `bin/` | Application code. |
| `rules/` | YARA rules scanned by default; drop-in — any `.yar`/`.yara` under it is compiled on the next scan ([yara-rules.md](yara-rules.md)). |
| `case-template/` | Scaffold copied into `~/cases/<CASE_ID>`. |
| `demo-cases/` | Bundled example studies (traces/reports; little or no evidence). |
| `benchmarks/` | Ground-truth grading datasets. |
| `share/.common/` | Install-time MITRE reference tables (copied into `~/cases/.common/`). |
| `.venv/` | Python virtualenv. |
| `cases` | **Compat symlink → `~/cases`** (created by `install.sh`, gitignored). |

## Why separate production cases?

- Customer evidence must not live inside a git working tree.
- Demos and benchmarks can be versioned, reset, and shared with the product.
- The dashboard defaults to `~/cases`; use `--demo` / `--benchmarks` for study data.

## Backwards compatibility

- `install.sh` detects the old inverted layout (`~/cases` → `Atlas/cases`) and migrates automatically.
- `Atlas/cases` remains a symlink to `~/cases` so older scripts that resolve `…/Atlas/cases/<id>` still work for production cases.
- Bundled studies are **no longer copied** into `~/cases`; they stay under `demo-cases/` and `benchmarks/`.
