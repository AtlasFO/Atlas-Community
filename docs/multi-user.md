# Multi-user deployment (shared VM over SSH)

*How to run Atlas for a team of analysts on one central Ubuntu VM, and how the
shared brain keeps growing — but only from people who commit or merge.*

Atlas was built single-user. This guide describes the supported multi-user
shape and the few adjustments that make it safe. The design principle: **one
Linux account per analyst, one Atlas clone per account, and the canonical brain
lives on the protected `main` branch.** Almost everything then isolates itself,
because per-user state already lives under each user's `$HOME`.

---

## The model at a glance

| Concern | How it's handled |
|---------|------------------|
| Per-user run state (`~/.cache/atlas/`, `~/cases/`, `~/.claude/`) | Isolated automatically by distinct `$HOME` — **no config needed** |
| Cases | Each analyst works their own cases under `~/cases` (`ATLAS_CASES_ROOT` default) |
| Reading the brain | Everyone gets brain injection from their clone's `brain/` |
| Proposing a learning | Anyone — candidates capture to their clone's `brain/inbox/` |
| **Growing the durable brain** | **Contributors only** — gated 3 ways (approve guard, pre-commit hook, protected `main`) |
| Receiving others' growth | `atlas brain sync` (fast-forwards from `origin/main`) |

> Why per-user clones and not one shared checkout? The brain contribution flow
> is git commits and merge requests. A shared working tree would collide on the
> git index whenever two maintainers commit. Per-user clones keep each analyst's
> tree clean and make "growth == a merge into `main`" literally true.

---

## One-time VM setup (admin)

1. **Create a Linux account per analyst.** Each must have its own `$HOME`. This
   single choice resolves the concurrency hazards (session-beacon hijack,
   shared call-id counter, answer-key-stash clashes) that only occur under a
   shared `$HOME`.
   ```bash
   sudo adduser alice && sudo adduser bob    # ... one per analyst
   ```
2. **Install the system forensic tools once.** They live in system paths
   (`/opt/zimmermantools`, `/usr/local/bin/vol`, `chainsaw`, …) and are shared.
   The per-user `install.sh` run below is idempotent about these.
3. **Protect `main` on both remotes** — this is the real "only mergers grow the
   brain" gate:
   - **GitHub**: Settings → Branches → add a rule for `main`: *Require a pull
     request before merging*, *Restrict who can push*, and limit merge rights to
     the maintainer team.
   - **Your private remote** (a self-hosted GitLab, say): protect `main` so
     no one can push and only maintainers can merge; require merge-request
     approval.

---

## Per-user setup (each analyst)

Run once per account:

```bash
git clone https://github.com/AtlasFO/Atlas-Community.git ~/Atlas
cd ~/Atlas
./install.sh              # builds ~/.venv, per-user sudoers, sets core.hooksPath
git config user.email "you@example.com"   # the identity the brain gate checks
```

Then provision model/secrets in the per-clone `.env` (gitignored — the installer
scaffolds it from `.env.example`):

```bash
$EDITOR ~/Atlas/.env
#   the provider settings `bin/atlas provider setup` writes: a shared team
#   key is fine, and one model pinned for everyone keeps runs comparable
```

> **Secrets note.** Atlas can also read keys from the GNOME keyring
> (`core/secrets.py`, service `atlas-sift`), but a keyring is unlocked per login
> *session* and is unreliable over headless SSH. On a shared VM, prefer the
> per-clone `.env` (or a root-owned, world-readable `/etc/atlas.env`) for the
> provider key rather than the keyring.

Add `~/Atlas/bin` to `PATH`, or symlink `bin/atlas` into `~/.local/bin`.

**Run cases from `~/cases`, not from inside the clone**, so run outputs never
dirty the git tree the brain workflow depends on. `install.sh` seeds `~/cases`
with the bundled studies.

---

## The brain: read freely, grow via merge

Capture and injection are on for everyone. The **durable** brain
(`brain/memory`, `brain/wiki`, `brain/logs`, `brain/indexes`) only grows through
a reviewed merge into `main`. Three layers enforce it:

1. **`atlas brain approve` guard** — refuses to promote a candidate unless your
   `git config user.email` is listed in `brain/CONTRIBUTORS`.
2. **`.githooks/pre-commit`** — blocks any commit touching the durable brain
   trees from a non-listed identity. `brain/inbox/` is **exempt**, so anyone can
   commit a *proposal*. (Enabled per clone by `install.sh` via
   `git config core.hooksPath .githooks`.)
3. **Protected `main`** — only maintainers can merge the PR/MR.

> While `brain/CONTRIBUTORS` is **absent or empty**, layers 1–2 are no-ops — a
> single-user checkout or the test suite behaves exactly as before. Keep at
> least one valid maintainer email in the file at all times.

### `brain/CONTRIBUTORS`

One git email per line; `#` comments and blank lines ignored; case-insensitive.
Keep this list in sync with the maintainer team that has merge rights on `main`.
Changing the file is itself a durable-brain change, so only a listed contributor
can commit it.

### Contribution flow

**Any analyst** who finds something worth keeping:
```bash
# their run already staged candidates under brain/inbox/memory-candidates/
git checkout -b brain/my-finding
git add brain/inbox/memory-candidates/<candidate>.md
git commit -m "brain candidate: <short desc>"   # inbox is exempt from the hook
git push private brain/my-finding                # open a merge request on the private remote
```

**A maintainer** turns proposals into durable knowledge:
```bash
atlas brain review                       # triage staged candidates
atlas brain approve brain/inbox/memory-candidates/<candidate>.md --yes
git add brain/ && git commit -m "brain: approve <desc>"   # hook allows (you're listed)
git push private main  # the private remote carries everything
```

> The community edition's `.gitignore` keeps brain notes, logs and indexes
> out of git (the lines under *Community edition*). A team that shares its
> brain through git deletes those lines first.

> **Push internal work to the private remote, never to GitHub.** Raw candidates
> (`brain/inbox/`) and other internal paths are refused on a `github.com` remote
> by the `.githooks/pre-push` guard. GitHub receives only a scrubbed snapshot —
> see *Publishing to GitHub* below.

**Everyone else** receives the growth:
```bash
atlas brain sync --remote private   # git pull --ff-only private main
```

Run `atlas brain sync` periodically (a per-user cron/login hook is fine) — but
**not** mid-investigation; it can update code as well as the brain. Team
clones track the private remote, which carries everything; never pull from
the GitHub snapshot, whose history is its own.

## Publishing to GitHub (scrubbed, public)

GitHub gets **only** a scrubbed snapshot — never raw captures, internal cases,
or contributor PII. Two mechanisms enforce this:

- **`.githooks/pre-push`** refuses INTERNAL paths / `internal/*`|`case/*`
  branches bound for a `github.com` remote (installed per clone alongside the
  pre-commit gate).
- **`atlas publish`** builds the public snapshot: it strips every path in
  [`.gitignore-public`](../.gitignore-public), regenerates indexes from the
  public subset, and scans `brain/wiki` + `brain/indexes` for case-specific
  identifiers before pushing.

```bash
atlas publish            # dry run — build + scan, push nothing
atlas publish --push     # push the scrubbed 'public' branch to origin (GitHub)
```

> `brain/CONTRIBUTORS` is internal PII (analyst e-mails) and is excluded from
> the public snapshot by `.gitignore-public`.

---

## What is isolated vs shared

| Path | Scope | Notes |
|------|-------|-------|
| `~/.cache/atlas/{session.json, call_id.counter, beacons/, answer-key-stash/}` | per-user | isolated by distinct `$HOME` |
| `~/cases/<case>/{analysis,exports,reports}` | per-user | each analyst's own cases |
| `~/.claude/projects/<case>/memory` | per-user | per-case scratch memory |
| `~/Atlas/brain/` | per-clone copy of canonical | synced via `atlas brain sync` |
| `/etc/sudoers.d/atlas-<user>` | per-user | least-privilege NOPASSWD for Atlas forensic binaries (`share/atlas-sudoers.in`) — not `ALL` |
| System tools (`/opt/...`, `/usr/local/bin/...`) | shared | installed once |

Because each analyst runs **their own** cases under **their own** `~/cases`,
the per-case collision points (the fixed-name trace JSON, the `evidence_index.db`
FTS store, evidence mounts, root-owned carver output) never overlap between
users. Do **not** have two users share one case directory — that is the one
scenario this deployment does not make safe.

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Second user has no passwordless sudo | Old single-file `/etc/sudoers.d/atlas` only covered the first installer. Re-run `install.sh` as that user (writes `/etc/sudoers.d/atlas-$USER` from `share/atlas-sudoers.in`). |
| `sudo_auth` after upgrade | Installer used to grant `NOPASSWD: ALL` or skip when any passwordless sudo existed. Re-run `install.sh` to refresh the least-privilege `Cmnd_Alias ATLAS_FORENSICS`. |
| `atlas brain approve` refuses with "not in brain/CONTRIBUTORS" | Working as intended. Add the identity to `brain/CONTRIBUTORS` (a maintainer commits it), or route the proposal through an MR. |
| `git commit` rejected: "refusing durable brain changes" | The pre-commit gate. Either your `git config user.email` isn't a listed contributor, or you staged durable-brain files — keep only `brain/inbox/` changes, or ask a maintainer. |
| `atlas brain sync` won't fast-forward | You have local commits or a dirty tree. Commit/stash or resolve with git; sync only fast-forwards. |
| Keys not picked up over SSH | Keyring isn't unlocked headless — put the hub key in `.env` (see Secrets note). |
| `atlas` runs on system python, missing deps | No venv found. `install.sh` builds `~/.venv`; `bin/atlas` uses `$REPO_ROOT/.venv` then `~/.venv` then system `python3`. |
