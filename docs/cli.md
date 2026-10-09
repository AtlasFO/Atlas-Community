# The `atlas` CLI — command guide

*Every `bin/atlas` command explained: what it does, when to reach for it, and worked examples — including running the forensic tools on a remote SIFT VM.*

This is the practical companion to [cli-reference.md](cli-reference.md) (complete flags),
[llm.md](llm.md) (backend setup), and
[try-it-out.md](try-it-out.md) (first walkthrough). If you're brand-new, read this page
top-to-bottom once; afterwards `bin/atlas <command> --help` shows the same examples inline.
For a quick in-terminal tour of how Atlas works end to end, run `atlas guide` (or a focused
topic, e.g. `atlas guide brain`).

**Contents:**
[Which command do I want?](#which-command-do-i-want) ·
[First-run checklist](#first-run-checklist) ·
[`run`](#atlas-run--the-workhorse) · [`interactive`](#atlas-interactive--supervised-run) ·
[`chat`](#atlas-chat--conversational-session) · [`train`](#atlas-train--graded-run) ·
[`review --live`](#atlas-review---live--unstick-a-running-investigation) ·
[`report`](#atlas-report--render-the-final-report) ·
[`rerun`](#incremental-re-investigation-atlas-rerun) ·
[`models` / `doctor` / `serve`](#atlas-models--doctor--serve--plumbing) ·
[`brain`](#atlas-brain--durable-cross-case-memory) ·
[Remote SIFT execution](#remote-sift-execution---remote) ·
[Exit codes](#exit-codes) · [Environment variables](#environment-variables) ·
[Usability tips](#usability-tips)

---

## Which command do I want?

| You want to… | Use |
|---------------|-----|
| Understand how Atlas works, end to end | `atlas guide` (try `atlas guide brain`) |
| Run a full autonomous investigation (Brain learns after) | `atlas run --case DIR` |
| Run one, but be consulted at decision points | `atlas interactive --case DIR -q "…"` |
| Talk to the analyst, drive tools by hand | `atlas chat --case DIR` |
| Lab run + independent reviewer grade | `atlas train --case DIR -q "…"` |
| Check whether a running investigation is stuck | `atlas review --live` |
| Change the animated LIVE panel look | `atlas skin` / `atlas run --skin matrix` |
| Read the newest report nicely in the terminal / as HTML | `atlas report [--format html]` |
| Re-investigate after evidence changed (keep Claim Graph) | `atlas rerun --case DIR` / `--no-agent` / `--assemble-report` |
| Compare investigation journal runs | `atlas rerun --diff run-0001..run-0002` |
| List models your LLM Hub key can use | `atlas models` |
| See which backend/model each role resolved to | `atlas doctor` |
| Run forensic tools on a *different* machine (a SIFT VM) | any of the above + `--remote HOST` — see [Remote SIFT execution](#remote-sift-execution---remote) |
| Manage Atlas's long-term memory | `atlas brain …` |
| Pull brain knowledge other contributors merged | `atlas brain sync` |

---

## First-run checklist

1. **Install** — `./install.sh` from the repo root (idempotent). Details: [try-it-out.md](try-it-out.md).
2. **A model** — `bin/atlas provider setup` connects any OpenAI-compatible backend and tests it (see [llm.md](llm.md)).
3. **Sanity check** — `bin/atlas doctor` prints what every role (analyst, `reason.*`, `dair.*`) resolved to. If something says `NOT SET`, fix it *before* running: missing reasoning backends silently degrade a run (findings are never challenged).
4. **A case directory** — either the bundled NITROBA-2008 brief (`~/Atlas/demo-cases/nitroba`) or a fresh copy of `case-template/`:
   ```bash
   cp -r ~/Atlas/case-template ~/cases/mycase
   # edit ~/cases/mycase/CASE.md  (Investigation Requests only)
   cp /path/to/image.E01 ~/cases/mycase/evidence/
   ```
5. **Run** — `bin/atlas run --case ~/cases/mycase`
   (`-q "…"` overrides CASE.md requests for this session; with neither, Atlas
   investigates the standard objective, *What happened on the Host(s)?*, and says so)

> **The `--case` flag is optional when you `cd` into the case first.** Every case-taking
> command detects a case directory from the cwd (it looks for `CASE.md`, `evidence/`, or
> `analysis/`). `cd ~/cases/mycase && atlas run` is equivalent.

> **Investigation objectives** live in `CASE.md` under `## Investigation Requests`.
> Atlas materializes them as `.atlas/investigation_tasks.json` and builds an
> investigation plan before the agent runs. `-q/--question` is an **optional
> override** for one session. A case with neither runs the standard objective
> rather than refusing to start.
>
> **Prior knowledge** goes under an optional `## What you already know` section:
> a working theory, indicators seen elsewhere (an address from the firewall, a
> hash from an alert), a time window, and facts about your environment (the
> admin jump host, a service account). A pasted list in a code fence counts too.
> Atlas seeds its searches from the indicators there and shows the model each
> statement with its id: a theory is a lead to test, an environment fact is
> context, never an allowlist. Nothing in that section becomes a finding by
> itself, and a miss is never taken as proof of absence.
> On a graded case (one shipping `ground_truth.json`) the indicators are not
> seeded, so the run stays comparable.
> The indicators also seed first-hour precautions on the dashboard's Response
> view, labelled as prior knowledge. See [architecture-case-driven.md](architecture-case-driven.md).

---

## `atlas run` — the workhorse

Runs one complete autonomous investigation: execution log → evidence hash verification →
competing hypotheses → the DAIR phase loop (Triage → Collect → Analyze → Scan → Report) →
gated final report. No confirmation prompts between steps.

```bash
atlas run --case ~/Atlas/demo-cases/nitroba -q "Who was responsible for the harassing posts?"

# From inside the case dir, quiet, machine-readable result on stdout:
cd ~/Atlas/demo-cases/nitroba && atlas run -q "…" --json

# Forensic tools execute on a remote SIFT VM; agent + LLM stay local:
atlas run --case ~/cases/mycase -q "…" --remote sift-lab
```

| Flag | What it does | When you need it |
|------|--------------|------------------|
| `--case DIR` | The case directory | Omit if your cwd is the case |
| `-q/--question` | Override of CASE.md Investigation Requests; without either, the standard objective | When you need a one-shot objective without editing CASE.md |
| `-L/--language en\|de` | Report and recommendation language, persisted in `.atlas/case_config.json` | Set once per case (the dashboard asks at case creation) |
| `--model ID` | Analyst model override | Trying a different hub model for one run |
| `--case-id ID` | Override the case ID from `CASE.md` | Distinct trace filenames for repeated runs |
| `--output-dir DIR` | Write `analysis/`/`exports/`/`reports/` elsewhere; evidence stays read-only in place | Keeping the case dir pristine; comparing runs side by side |
| `--remote HOST` | Execute forensic tools on a SIFT VM | Evidence or tooling lives on another machine — [details](#remote-sift-execution---remote) |
| `--all-tools` | Expose all ~270 tool schemas up front (~36k tokens) | Only for large-context models; normally namespaces lazy-load |
| `--interactive` | The agent may consult you at decision points | Same as `atlas interactive` |
| `--quiet` | Suppress per-turn narration | Logs/cron |
| `--json` | Final stats as JSON on stdout (implies `--quiet`) | Scripting |

**What you'll see while it runs:** a per-turn narration of tool calls and findings, plus a
live status banner (turn, elapsed, tool calls/errors, findings, token spend). At case open it
prints a **live dashboard URL** — open it in a browser to watch the trace fill in real time
(`./dashboard.sh` must be running).

**Where output lands** (all under the case dir, or `--output-dir`):

```
reports/<CASE_ID>_investigation_report.md   ← the analyst report
reports/<CASE_ID>_trace.{json,md}           ← exported audit trail
analysis/<CASE_ID>_trace.json               ← live trace (dashboard input)
exports/                                    ← raw tool output (CSV, EVTX exports, …)
```

---

## `atlas interactive` — supervised run

Exactly `atlas run`, but the agent is allowed to pause and ask **you** at genuine decision
points (via the `atlas_ask_analyst` tool) — e.g. "two plausible pivots, which first?" or
"scope: is host X in bounds?". Between questions it works autonomously.

```bash
atlas interactive --case ~/cases/mycase -q "How did the attacker get in?"
```

Use it when you know things the evidence doesn't say (scope, business context, what the
customer already confirmed) and want them injected mid-run instead of baked into the brief.

---

## `atlas chat` — conversational session

An open-ended analyst session: no autonomous phase loop, you drive. Ask questions, have it
run specific tools, explore evidence. Same tool access and safety rails as `run`.

```bash
atlas chat --case ~/cases/mycase     # case-aware
atlas chat                            # no case: general Q&A with the toolbox available
```

Good for: post-run follow-ups ("show me the prefetch entries for that binary"), poking at a
single artifact without a full investigation, or learning what a tool does before trusting a
full run with it.

---

## `atlas skin` — the live dashboard's animation

The CLI's live panel has five skins. `atlas skin` lists them and marks the
active one; `atlas skin NAME` makes one the default (saved in
`~/.atlas/ui.json`); `--skin NAME` on `run`/`train`/`interactive`/`chat`
uses one for a single session; `ATLAS_LIVE_SKIN=NAME` does the same from the
environment. Precedence: flag, then environment, then the saved default.

| Skin | Look |
|---|---|
| `atlas` | Classic animated Atlas figure with the neon LIVE panel (default) |
| `matrix` | Digital rain with the run's data centred in the cascade |
| `radar` | Sonar sweep — blips for tools, findings and alerts |
| `wave` | Oscilloscope heartbeat of the investigation signal |
| `aquarium` | Underwater tank — seaweed, bubbles and fish |

Cosmetic only: the skin never changes what a run does or records.

## `atlas train` — graded run

A **clean-slate run plus an independent review**. The case's `analysis/`, `exports/`, and
`reports/` are cleared first, the investigation runs to completion, and then a *separate*
reviewer model — fresh context, no tools — grades the run from its trace, report, and (when
the case ships one) the `ground_truth.json` answer key.

```bash
atlas train --case ~/Atlas/demo-cases/nitroba -q "Who was responsible for the harassing posts?"

# Keep prior state instead of clearing; pin a specific reviewer:
atlas train --case DIR -q "…" --no-clear --review-model <model-id>
```

The review lands in `reports/<CASE_ID>_run_review.md` with a verdict — `STRONG` /
`ACCEPTABLE` / `NEEDS WORK` — and recommendations *only when the run needs them*.
Afterwards, background investigation learning may stage a few high-quality
candidates for Dashboard → Brain Review (nothing is promoted without your
`atlas brain approve`).

Brain flags: `--no-brain` disables the second brain **entirely** — no
memory/concept injection into the prompt (it sets `ATLAS_NO_BRAIN` for the run)
and no post-run learning. `--no-brain-capture` keeps injection/learning but
skips only the legacy review-bullet staging step.

**`atlas run` is the normal investigation command** and also queues background
Brain learning when the run finishes. `atlas train` adds an independent
reviewer (labs / graded cases). Optional `--capture-brain` additionally stages
legacy review/self-correction candidates.

**Careful:** the clear step is destructive to prior run output in that case dir (evidence is
never touched). Use `--no-clear` to keep prior state, or `--output-dir` to run in an isolated
mirror directory and leave the real case alone.

Scriptable exit codes: `0` ended through one of the loop's endings and the coverage
verdict is `complete`, `2` the run was cut off before any of them (turn cap, wall clock,
deadlock, transport), `3` review says NEEDS WORK, `4` it ended cleanly but coverage or
beliefs do not support calling it complete. A run the loop closed out itself — it wrote
the reports once the gate passed, rather than the model calling `atlas_finish` — is an
ending like any other, not a failure.

---

## `atlas review --live` — unstick a running investigation

Reads the on-disk trace of an **in-flight** run — read-only, safe to point at a live
investigation — and answers "is it stuck, and what would unstick it?".

```bash
atlas review --live                             # the active run (found via ~/.cache/atlas/session.json)
atlas review --live --trace path/to/trace.json  # a specific trace
```

A deterministic stall detector (no LLM, costs nothing) checks for the classic stuck
signatures first — spinning in one phase, high tool-failure rate, zero findings after many
calls, repeated-command rabbit holes. A healthy, progressing run is never flagged. Only if it
looks stuck does the reviewer model write concrete unstick steps to
`reports/<CASE_ID>_live_review.md`.

Exit code `3` = stalled, so a babysitter loop is one line:

```bash
while sleep 600; do atlas review --live --json || [ $? -eq 3 ] && notify-send "Atlas run stalled"; done
```

Without `--live`, `atlas review --case DIR` grades the run as it stands, the review
`atlas train` writes (`reports/<CASE_ID>_run_review.md`, replacing one a train run
wrote; exit `3` = NEEDS WORK). It reads only the trace file, never the running process;
accuracy and the TTP coverage figure are computed from the trace's own findings. Either way
the review goes to the case the trace belongs to, never to the directory the command ran in.

---

## `atlas report` — render the final report

Finds the newest report in the case and renders it — in the terminal by default, or as
Markdown, HTML or PDF for sharing.

```bash
atlas report                                   # newest report, pretty-printed in the terminal
atlas report --format html                     # writes <report>.html next to the report
atlas report --format pdf                      # writes <report>.pdf next to the report
atlas report --format html --output /tmp/r.html
```

PDF renders from the report's own Markdown, so it says what the Markdown says.
It needs no system libraries, only the `fpdf2` package from `requirements.txt`.
Install `fonts-dejavu-core` (the installer does) for a typeface that covers
more than Latin-1; without it the export still works, and any character no
available font can draw is replaced with a marker and counted in a line at the
end of the document. The Markdown stays the record.

---

## Incremental re-investigation (`atlas rerun`)

After evidence is added, a question or a fact is added to CASE.md, or tools improve, prefer **`atlas rerun`** over deleting the case and starting fresh. Rerun keeps the Claim Graph, marks only the findings the change touches for review, and starts the investigator only when the pre-run pass found work: evidence added, changed or removed under `evidence/`; a question still open; a finding under review; a fact added to or withdrawn from *What you already know*. When nothing changed, it says so and only regenerates stale report sections.

```bash
# See what changed (no catalog/journal writes)
atlas rerun --case ~/cases/mycase --dry-run

# Record the changes only: fingerprints, dirty set, needs_review, brief, journal (no AI)
atlas rerun --case ~/cases/mycase --no-agent

# Continue: the investigator starts from the Rerun Brief when there is work
atlas rerun --case ~/cases/mycase

# Add a fact to the brief's "What you already know" (kept as analyst context), then continue
atlas rerun --case ~/cases/mycase -q "IP 10.0.0.5 is a legitimate admin IP"

# Report projection helpers
atlas rerun --assemble-report
atlas rerun --regenerate-sections    # AI rewrite of stale sections (needs a connected model)

# Journal
atlas rerun --list-runs
atlas rerun --diff run-0001..run-0002
```

**Planes:** Plane A is deterministic (fingerprints → dependency index → `needs_review` → stale sections; CASE.md reconciled into tasks and analyst context; the work summary). Plane B is the investigator, started from the Rerun Brief whenever Plane A found work, unless `--no-agent`. Details: [Investigation architecture](architecture-investigation.md), [Investigation state](investigation-state.md), [CLI reference — rerun](cli-reference.md#atlas-rerun).

---

## `atlas models` / `doctor` / `serve` — plumbing

```bash
atlas models     # model ids available to your LLM Hub key (use these with --model / --analyst-models)
atlas doctor     # resolved configuration: base URL, key present?, model per role
atlas serve      # run the Atlas MCP server on stdio — for connecting other MCP clients
```

`atlas doctor` is the first thing to run when behavior seems off. In particular it warns when
Legacy note: `ANTHROPIC_API_KEY` is ignored (Anthropic backends removed). Prefer hub:
Claude, so set `REASON_BACKEND=llmhub` / `DAIR_BACKEND=llmhub` explicitly to force the hub.

---

## `atlas brain` — durable cross-case memory

Atlas's "second brain": knowledge that survives across cases (tool quirks, techniques, actor
notes, run summaries). Runs **inject** relevant notes in and **stage candidates** to
`brain/inbox/` after — but a candidate becomes durable only when a **contributor** approves
it and the change is **merged** to the canonical `main`. Growth is gated by
`brain/CONTRIBUTORS` (anyone may propose); `atlas brain sync` pulls merged growth. For the
full model, run `atlas guide brain`.

```bash
atlas brain review                 # list staged candidates (add --risk for sensitive-flagged ones)
atlas brain approve <candidate>    # promote into durable memory (contributors only)
atlas brain reject <candidate> --reason "too case-specific"
atlas brain sync                   # fast-forward this clone to pull merged brain growth
atlas brain search "prefetch"      # search notes
atlas brain stats                  # note counts + JSON snapshot
atlas brain report --period week   # Markdown learning report
atlas brain new --type technique --title "…"   # hand-write a note
atlas brain new --type environment --client acme-corp --title "…"  # client baseline (real engagements only)
atlas brain capture --case DIR     # legacy staging from an already-finished run
atlas brain learn --case DIR       # quality-first investigation learn (also auto after atlas run/train)
atlas brain globe                  # knowledge-graph data for the dashboard's Brain Earth view
```

**Recommended workflow:** use `atlas run` for real investigations. Background
Brain learning starts automatically when the run finishes. Open Dashboard →
**Brain Review** to approve or reject candidates. Use `atlas train` for lab
cases that need an independent reviewer. Design:
[architecture-brain.md](architecture-brain.md).

Disable learning with `ATLAS_NO_BRAIN_LEARN=1`; disable all Brain with
`ATLAS_NO_BRAIN=1` / `--no-brain`.
See `brain/AGENTS.md` for the note schema and philosophy.

### Multi-user: the brain contributor gate

On a shared VM the brain is shared through git and grows **only from people who commit or
merge**. Three layers enforce it:

1. **`atlas brain approve`** refuses unless your `git config user.email` is listed in
   `brain/CONTRIBUTORS`.
2. **A pre-commit hook** (`.githooks/pre-commit`, enabled by `install.sh` via
   `git config core.hooksPath .githooks`) blocks commits touching
   `brain/{memory,wiki,logs,indexes}` and `brain/CONTRIBUTORS` from non-listed identities.
   `brain/inbox/` proposals are exempt, so anyone can suggest a candidate on a branch +
   merge request.
3. **Protected `main`** on the remotes restricts who can merge.

The gate is inert while `brain/CONTRIBUTORS` is absent, so single-user checkouts and the
test suite are unaffected. Non-contributors still get injection and can propose; they
receive merged growth with `atlas brain sync`. Full provisioning + maintainer runbook:
[multi-user.md](multi-user.md).

---

## Remote SIFT execution (`--remote`)

**What it is:** run the CLI, the agent loop, and all LLM traffic on your local machine while
the *forensic tool subprocesses* (Volatility, Sleuth Kit, EZ Tools, YARA, …) execute over SSH
on an external SANS SIFT VM. Useful when:

- the evidence is large and already sits on a lab VM — don't copy it, investigate in place;
- your laptop lacks the SIFT toolchain (or the RAM/disk for a 40 GB E01) but a lab VM has both;
- policy says evidence never leaves the lab network, but the analyst tooling may run outside it.

What stays local: the `atlas` process, the model conversation, the execution trace, the
dashboard. What runs remote: only the tool subprocesses, routed through the single executor
choke point — same output caps, timeouts, and read-only evidence enforcement as local runs.

### 1. One-time setup: register the VM

Remote hosts are **pinned in a config file**, never passed as raw hostnames — the agent can
only reach machines you pre-registered. Create `~/cases/.common/live_hosts.json` on the
*local* machine:

```json
{
  "sift-lab": {
    "user": "sansforensics",
    "host": "10.0.0.12",
    "identity": "~/.ssh/atlas_sift",
    "port": 22
  }
}
```

- `identity` is an SSH private key with non-interactive access to the VM (create a dedicated
  key: `ssh-keygen -t ed25519 -f ~/.ssh/atlas_sift` and add the `.pub` to the VM's
  `authorized_keys`). If omitted, the `ATLAS_LIVE_SSH_KEY` env var is used.
- The key name (`sift-lab` here) is what you pass to `--remote`.
- The VM needs the SIFT toolchain installed (it's a SIFT Workstation — run `./install.sh`
  there once if unsure); the login shell's PATH must find the tools.

Verify connectivity before a long run:

```bash
ssh -i ~/.ssh/atlas_sift sansforensics@10.0.0.12 -- vol3 --help >/dev/null && echo OK
```

### 2. Pick an evidence mode

| Mode | Evidence lives… | What happens | Choose it when |
|------|-----------------|--------------|----------------|
| `resident` (default) | **on the VM** already | Nothing is copied. Your case brief (`CASE.md`) references VM-side paths (e.g. `/cases/foo/evidence/disk.E01` *as seen from the VM*). Outputs the tools write also land on the VM. | Big images, evidence that must not leave the lab |
| `copy` | **on your local machine** | Before the run, the case's `evidence/` (and brief) is rsynced up to a per-case workspace on the VM (default `~/atlas-workspace`, override with `--remote-workspace`). Local paths in every tool command are transparently remapped to the workspace. Afterwards `analysis/`, `exports/`, and `reports/` are rsynced back down. | Small/medium evidence, you want all results local when it's done |

### 3. Run

```bash
# Evidence already on the VM (resident, the default):
atlas run --case ~/cases/mycase -q "…" --remote sift-lab

# Evidence local, copy it up and sync results back:
atlas run --case ~/cases/mycase -q "…" --remote sift-lab --remote-mode copy

# Custom workspace on the VM for copy mode:
atlas run --case ~/cases/mycase -q "…" --remote sift-lab \
    --remote-mode copy --remote-workspace /data/atlas-workspace

# train and interactive accept the same flags via the shared run path:
atlas interactive --case ~/cases/mycase -q "…" --remote sift-lab
```

The trace records each remote call with its host and the exact remote command
(`[remote:sift-lab] (cd …) vol3 …`), so the audit trail stays complete. Truncated remote
output is spilled to a local file just like local runs.

### Remote-mode notes & troubleshooting

| Symptom / question | Answer |
|--------------------|--------|
| `host 'x' config is missing required keys` | The entry in `~/cases/.common/live_hosts.json` needs at least `user` and `host`. |
| `no identity file in config and ATLAS_LIVE_SSH_KEY env unset` | Add `"identity": "~/.ssh/…"` to the host entry, or export `ATLAS_LIVE_SSH_KEY`. |
| Every tool call fails instantly | SSH itself is failing — test the `ssh -i … user@host -- <tool> --help` line above. Passphrase-protected keys need an `ssh-agent`. |
| Tools "not found" remotely but installed | They're not on the login shell's PATH. Remote commands run under `sh -lc`, so ensure the VM's profile exports the SIFT tool paths. |
| Resident mode: agent can't find the evidence | The brief must use **VM-side** paths. Your local `evidence/` dir is irrelevant in resident mode. |
| Copy mode: first sync is slow | It's a full rsync of `evidence/` (`-az`, compressed). Subsequent runs against the same workspace only transfer deltas. |
| Where did copy-mode outputs go? | Synced back to the local case's `analysis/` / `exports/` / `reports/` when the run ends (even on failure — the sync runs in a `finally`). |
| Is evidence still read-only? | Yes — the same `core/paths.py` write-guard applies; remote execution goes through the identical executor choke point. |
| Can I mix? | Per run, one host + one mode. Different runs may target different hosts. |

Related but different: the **`live.*` namespace** ([live-endpoint-testing.md](live-endpoint-testing.md))
runs *triage probes against a suspect host*; `--remote` runs *Atlas's own toolbox on a trusted
lab VM*. Both share the pinned-host config file and SSH plumbing.

---

## Exit codes

Designed for scripting — every path is distinguishable:

| Command | 0 | 1 | 2 | 3 |
|---------|---|---|---|---|
| `run` | finished | LLM/config error | run stopped unfinished | — |
| `train` | finished, review OK | reviewer/LLM error | run didn't finish | review says NEEDS WORK |
| `review --live` | healthy | reviewer error | — | run is stalled |
| `review` | graded, review OK | reviewer error | — | review says NEEDS WORK |

```bash
atlas train --case DIR -q "…" --json > result.json
case $? in
  0) echo "clean run" ;;
  2) echo "did not finish — check the trace" ;;
  3) echo "needs work — read reports/*_run_review.md" ;;
esac
```

---

## Environment variables

Set in `~/Atlas/.env` (loaded first), a case-local `.env` (fills unset vars only), the GNOME
Keyring (`bin/atlas-secret set NAME`), or the environment. `atlas doctor` shows the result.

| Variable | Role |
|----------|------|
| `LLMHUB_API_KEY` (alias `TSYSTEMS_API_KEY`) | T-Systems LLM Hub key, when the hub is one of your providers |
| `LLMHUB_MODEL` | Default hub model for all roles |
| `ATLAS_AGENT_MODEL` | Analyst model override (also `--model`) |
| `REASON_BACKEND` / `REASON_URL` / `REASON_MODEL` / `REASON_API_KEY` | Adversarial-reviewer role |
| `DAIR_BACKEND` / `DAIR_URL` / `DAIR_MODEL` / `DAIR_API_KEY` | Phase-director role |
| `ATLAS_REVIEW_MODEL` | Reviewer for `train`/`review` (then the reviewer provider's model, then `REASON_MODEL`) |
| `ATLAS_AGENT_PROVIDER` / `ATLAS_REVIEW_PROVIDER` / `ATLAS_REPORT_PROVIDER` | Provider per role (the wizard and Settings → Providers, Roles in a run, write these); an explicit `*_MODEL` above outranks the provider's model |
| `ATLAS_RUN_NOTIFY_EMAIL` | Mail this address when a terminal run ends (needs the SMTP settings; dashboard-started runs mail whoever pressed Start) |
| `ATLAS_MODEL_CONTEXT_TOKENS` | Override the probed context window |
| `ATLAS_REMOTE_SIFT` / `ATLAS_REMOTE_MODE` / `ATLAS_REMOTE_WORKSPACE` / `ATLAS_REMOTE_LOCAL_ROOT` | Remote execution — the `--remote*` flags set these for you |
| `ATLAS_LIVE_SSH_KEY` | Fallback SSH identity when a host entry has none |
| `ATLAS_AGENT_INPUT_TPM` | Proactive rate-limit pacing (default 400000; `0` disables) |
| `ATLAS_AGENT_RATE_LIMIT_WAIT` | Max total wait on 429s (default 600 s) |
| `ATLAS_AGENT_CONTEXT_CHARS` | Context sent per turn (derived from the probed window; ~3 000 000 chars for 1M tokens) |
| `ATLAS_THEME` | CLI colour theme: `neon` (default) / `atlas` / `mono` |
| `ATLAS_LIVE_SKIN` | LIVE dashboard animation: `atlas` (default) / `matrix` / `radar` / `wave` / `aquarium` (also `atlas skin` / `--skin`) |
| `ATLAS_VOL_TIMEOUT` | Volatility timeout on slow hardware |
| `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` / `OTX_API_KEY` / `URLSCAN_API_KEY` / `MISP_URL`+`MISP_API_KEY` | Optional IOC enrichment — never block a run; a failed lookup is reported as failed, not as clean |

---

## Usability tips

- **Watch it live.** Start `./dashboard.sh` once; every run prints its dashboard URL at case
  open. The Trace Viewer / Investigation Chain / Graph views update as the run progresses.
- **Second terminal = health check.** `atlas review --live` any time, read-only, never
  disturbs the run.
- **`--json` everywhere you script.** `run`, `train`, `review` all emit a
  machine-readable result on stdout with `--json`; narration goes to stderr.
- **Keep cases pristine with `--output-dir`.** Evidence is symlinked read-only into a mirror
  directory; all outputs land there. `train --output-dir` even scopes its clear step to the
  mirror.
- **Themes & terminals.** `ATLAS_THEME=mono` for logs/CI or low-color terminals; `atlas` for
  the classic red look. Separately, pick the animated LIVE panel with `atlas skin` (`atlas` /
  `matrix` / `radar` / `wave` / `aquarium`), one-shot via `atlas run --skin matrix`, or
  `ATLAS_LIVE_SKIN`. Preference lands in `~/.atlas/ui.json`.
- **Don't reach for `--all-tools`.** Namespaces lazy-load exactly when a phase needs them;
  the flag exists for large-context models and costs ~36k tokens of schemas every turn.
- **When in doubt: `atlas doctor` first, then `atlas models`.** Most "it behaves weirdly"
  reports are a role silently resolving to a different backend than intended.
