# Atlas — detailed install walkthrough & troubleshooting

A longer companion to the root [README](README.md) — full step-by-step,
plus a troubleshooting table for when something doesn't go cleanly. For
the short version, use the README's Install section.

Two ways to install Atlas — pick one:

1. **Normal** (recommended for most people) — a plain Ubuntu 24.04 /
   Debian 12 host, bare metal/VM/Docker (see `docs/docker.md`). Fastest
   path if you don't already run SIFT and don't need its full desktop
   toolkit. Start at step 1 below, skip 0b entirely.
2. **SIFT Workstation** — provision SIFT first (step 0b, via `cast`),
   then continue with the exact same steps 1+ below; `install.sh` detects
   SIFT and only installs whatever it didn't already provide. Choose this
   if you want SIFT's full desktop toolkit alongside Atlas, or already
   run/plan to run SIFT for other work.

## 0. Get a host

1. Ubuntu 24.04 or Debian 12 — bare metal, cloud VM, or local VM. (Ubuntu
   22.04 needs a newer python3 first, since Atlas requires Python 3.11+;
   other Debian/Ubuntu versions are attempted best-effort; anything else is refused — see
   `docs/other-distros.md`.)
2. Minimum host requirements:
   - **CPU**: 4 cores minimum, 8+ recommended — Plaso timelines, YARA/
     floss/capa static analysis, and carving are all CPU-bound and scale
     with cores available.
   - **RAM**: 8 GB minimum, 16 GB recommended. Volatility 3 and Plaso are
     the two RAM-hungry tools here — processing a large memory image or a
     full-disk timeline can need noticeably more than the baseline; budget
     32 GB+ if you regularly work with memory images over ~8 GB or very
     large disks.
   - **Disk**: plan **10 GB** for the install itself — the tools and
     Python packages take about 2 GB, the rest is headroom for
     distribution packages and the .NET runtime. Evidence storage is
     separate and scales with what you're investigating: a single disk
     image alone is commonly **30–500 GB or more**, and derived output
     (timelines, carved files, exports) adds on top — budget well beyond
     the evidence's own size, especially for multi-image cases. Atlas also
     enforces a runtime floor (`ATLAS_MIN_FREE_DISK_MB`/`_PCT` in `.env`,
     default 2 GB / 2% of the volume, whichever is larger) and refuses to
     start, or aborts a running job, if free space drops below it — a
     safety net against filling the disk mid-run, not a sizing guide.
   - Network access to:
     - An LLM backend — the Telekom LLM Hub, OpenAI, a local server, or any
       other OpenAI-compatible endpoint (required for investigations; see
       `docs/llm.md`)
     - `apt` / GitHub (the installer downloads the tools no distribution
       packages — Chainsaw, Hayabusa, RegRipper, EZ Tools, INDXParse,
       DensityScout, the Didier Stevens PDF tools, Detect It Easy,
       Velociraptor, jphide — at the versions pinned in
       `install-versions.env`)

   **Self-hosting a local LLM** (e.g. `vllm serve
   fdtn-ai/Foundation-Sec-8B-Reasoning`, see the README's closing note) has
   its own, much larger requirements — GPU VRAM and RAM scale with
   whichever model you choose, and aren't part of the baseline above (which
   assumes an API-based backend: the Hub, OpenAI, or any other remote
   OpenAI-compatible endpoint). Check your chosen model's own requirements
   if you go that route.

## 0b. (SIFT path only — skip to step 1 for a plain host) Provision a SIFT Workstation via `cast`

```bash
# Install cast (resolves the current release tag first — cast's release
# filenames are versioned and change every release, so a hardcoded
# version number would go stale):
CAST_VERSION="$(curl -fsSL https://api.github.com/repos/ekristen/cast/releases/latest | grep -Po '"tag_name": "\K[^"]*')"
wget "https://github.com/ekristen/cast/releases/download/${CAST_VERSION}/cast-${CAST_VERSION}-linux-amd64.deb"
sudo dpkg -i "cast-${CAST_VERSION}-linux-amd64.deb"
# arm64 host? swap amd64 for arm64 in both lines above.

# Install SIFT itself:
sudo cast install teamdfir/sift-saltstack
```

`cast` (https://github.com/ekristen/cast) is the official SaltStack-based
installer for SIFT — successor to the old `sift-cli`. Continue to step 1
once it finishes.

## 1. Clone the repo

```bash
git clone https://github.com/AtlasFO/Atlas-Community.git ~/Atlas
cd ~/Atlas
```

**Not tracked in git (on purpose):**

| Left out | Why |
|----------|-----|
| `.env` | Contains API keys — never share |
| `.venv/` | Machine-specific; `install.sh` recreates it |
| Production `~/cases` evidence | Huge / case-sensitive; create your own cases |

## 2. Run the installer

```bash
cd ~/Atlas
chmod +x install.sh
./install.sh
# Fully unattended (accepts every prompt's default; needed for scripted/CI use): ./install.sh --yes
```

What it does (idempotent — safe to re-run):

- Detects your OS, whether you're root, and whether you're in a container — and adapts
- Installs `python3` if it's missing, then checks it's 3.11+ (fatal only if
  the installed/available version is still too old); also checks `dotnet`
  (only needed for EZ Tools, not fatal if absent)
- Installs missing apt packages (venv, pip, sleuthkit, ewf/bde/vshadow tools, pst/pff
  tools, libesedb/libevt exporters, foremost, scalpel, testdisk, clamav, exiftool,
  ssdeep, hashdeep, steghide, outguess, qemu-utils, tcpdump, ngrep, …)
- Installs Volatility 3 (pip) and Plaso (GIFT PPA on Ubuntu, pip elsewhere) — the two big
  pieces a SIFT box would otherwise have provided
- Installs the tools no distribution packages, at the versions pinned in
  `install-versions.env`: Chainsaw with the SigmaHQ rule set and its own event-log and
  $MFT rules, Hayabusa with its rule set, RegRipper,
  the EZ Tools (with SrumECmd; needs the .NET 9 runtime), INDXParse (pip, into the venv), DensityScout, the
  Didier Stevens PDF tools, Detect It Easy, Velociraptor's client binary, jphide/jpseek.
  Every one of these is download-and-warn — a failed download never stops the install
- Optional network monitoring (zeek, suricata): `--with-network-tools`
- Copies the MITRE ATT&CK tables (techniques, groups, software, mitigations) to
  `~/cases/.common/`, refreshing them whenever the repository's copy changed
- Shows you the exact sudoers rule before installing **least-privilege passwordless sudo**
  for Atlas forensic binaries only (`/etc/sudoers.d/atlas-$USER` from
  `share/atlas-sudoers.in` — mount/loop/carve/network; **not** `NOPASSWD: ALL`) — skipped
  automatically if you're already root (e.g. building a Docker image)
- Creates `~/Atlas/.venv` and installs Python deps from `requirements.txt`
- Copies `.env.example` → `.env` if `.env` is missing, and offers to connect an LLM backend now (`bin/atlas provider setup`)
- Sets up `~/cases` for production investigations
- Wires `atlas-dashboard`
- Offers optional start-on-boot (systemd) and LAN listen (HTTPS on 0.0.0.0).
  Both default off. Re-run `./install.sh --with-dashboard-service --with-dashboard-lan`
  on an existing VM. First visit still creates the admin. Org certs go in
  `/etc/atlas/dashboard/tls.crt` + `tls.key` (no UI). Does not open the firewall.
- Runs a quick post-install check (`pytest -m install_smoke`, seconds; warnings are OK, install still completes). The full test suite runs only with `--with-full-tests` or when you answer yes to its question — several minutes on a workstation, 30 minutes or more on a small VM
- Checks every program a tool can call and writes `~/.cache/atlas/install_report.json`;
  the same board is on the dashboard under **Settings → Tool health**, which says for
  each missing program what should have installed it. A tool whose program is missing is
  marked in the model's manifest so a run never spends a call finding out
- Writes `.install-manifest.json` — exactly what `./uninstall.sh` reads to remove precisely
  what got installed, and nothing you already had. A rerun adds what it installed to the
  record of earlier runs, and a run that stops midway still records what it had done

## 3. Add your API keys

Easiest: the interactive wizard (also offered by `install.sh` itself):

```bash
bin/atlas provider setup
```

Walks you through the Telekom LLM Hub, OpenAI, a local/self-hosted server,
or any other OpenAI-compatible endpoint, and tests the connection before
saving. Nothing is pre-selected. The dashboard's **Settings → Providers** section
does the same and assigns each model role to a provider. Manual alternative:

```bash
cp -n .env.example .env    # only if install did not already create .env
nano .env                  # a key can also go in with: bin/atlas-secret set <NAME>
```

**Optional enrichment** (lookups degrade gracefully if empty; also under
Settings → Enrichment keys, where a saved key takes effect immediately):

```bash
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
URLSCAN_API_KEY=
MISP_URL= / MISP_API_KEY=
```

**Do not copy someone else's full `.env` into chat or email if you can avoid
it** — prefer `bin/atlas-secret set <KEY>` (OS keyring) over plaintext where
possible.

Details: `docs/llm.md`

## 4. Smoke-check (no investigation yet)

```bash
# Dashboard (no Hub key needed to browse bundled demos)
./dashboard.sh --demo
# → http://127.0.0.1:8765
# LAN (after --with-dashboard-lan): https://<host-ip>:8765
# Org TLS: /etc/atlas/dashboard/tls.crt + tls.key, then restart atlas-dashboard
# Behind a reverse proxy (nginx/Caddy for org TLS or HTTP/2): proxy to the
#   loopback port, pass the Host header through, add the proxy's DNS name to
#   ATLAS_DASHBOARD_EXTRA_HOSTS, and do not buffer /_dashboard/api/events
#   (it is a server-sent event stream; nginx: proxy_buffering off).
# Cases root on a network share: WATCHFILES_FORCE_POLLING=1 in .env, so the
#   live updates poll the share instead of waiting for inotify.

# CLI present?
bin/atlas --help
```

## 5. First real run (demo case)

```bash
# the capture comes from the source in docs/datasets.md
mkdir -p ~/Atlas/demo-cases/nitroba/evidence
cp /path/to/nitroba.pcap ~/Atlas/demo-cases/nitroba/evidence/
bin/atlas run --case ~/Atlas/demo-cases/nitroba \
  -q "Who was responsible for the harassing posts?"
```

Report + trace land under `demo-cases/nitroba/reports/`.

## 6. Your own production case

```bash
mkdir -p ~/cases
cp -r ~/Atlas/case-template ~/cases/MyCase
# Edit ~/cases/MyCase/CASE.md — put evidence under ~/cases/MyCase/evidence/
bin/atlas run --case ~/cases/MyCase              # -q "..." to override CASE.md for one run
```

Or create it in the dashboard (*New case*: id, investigation requests,
report language — English is recommended, the models are trained mostly on
it) and press *Start*. A case that states no question is investigated under
the standard objective, *What happened on the Host(s)?*.

## 7. After the install: the Settings page

The first visit to the dashboard creates the admin account. Settings then
holds everything the installer could not decide for you: LLM providers and
which of the five model roles uses which; enrichment keys; users, roles and how
long a session lasts; mail (password resets, and a note to whoever started a
run when it ends); the network share; plugins; the tool-health board; and a
button that refreshes the MITRE ATT&CK tables from MITRE's current release.
Tour: `docs/dashboard.md`.

## Troubleshooting

| Symptom | What to try |
|---------|-------------|
| `python3 -m venv` fails | `sudo apt-get install -y python3-venv python3-pip` then re-run `./install.sh` |
| `dotnet` missing | Optional — only the `ez.*` Windows artifact parsers need it. Install a .NET 9 runtime: `sudo apt-get install -y dotnet-runtime-9.0` (enable `packages.microsoft.com` first if needed), then re-run `./install.sh` |
| Hub / 401 errors | Check `LLMHUB_API_KEY` and `LLMHUB_BASE_URL` in `.env` |
| Email tools missing | `sudo apt-get install -y pff-tools pst-utils` |
| `vol.*` / memory forensics unavailable | Check `.venv/bin/vol --help` runs; re-run `./install.sh` to retry the `pip install volatility3` step |
| `plaso.*` / timeline tools unavailable | Ubuntu: check `apt-cache policy plaso-tools` shows `ppa:gift/stable`; Debian or PPA failure: `.venv/bin/pip install plaso` |
| Disk-image mount/carve tools fail in Docker | Loop-device access isn't granted by default — see `docs/docker.md` (`--privileged` or `--cap-add SYS_ADMIN --device /dev/loop-control`) |
| Disk full mid-run | Free space; Atlas refuses tools below ~2 GiB free (see `.env`) |
| `atlas run` exits before starting: passwordless sudo required | Run `bin/atlas-sudoers` (one password), then retry. Or `./install.sh`. Check: `bin/atlas-sudoers --check`. |
| `failure_class: sudo_auth` mid-run | Same fix: `bin/atlas-sudoers`. File-backed `tsk.mmls` on `analysis/*.raw` needs **no** sudo. |
| Need to edit allowed binaries | Update `share/atlas-sudoers.in` + `share/atlas-sudoers.bins`, then run `bin/atlas-sudoers` |
| A tool shows *missing* on Settings → Tool health | The row names what should have installed it; re-run `./install.sh` (idempotent) or install it by hand as the row says. *Optional* rows (Detect It Easy, rizin, zeek/suricata) are not errors |
| A run recorded no findings for a technique you expected | Check Settings → Tool health for the tool's program first; a missing program is marked in the model's manifest and never called |
| Want to remove everything `install.sh` added | `./uninstall.sh` (add `--dry-run` to preview first) — never touches `~/cases`, `.env`, or the repo checkout |
| `install.sh` warns that `xmount` is not installable alongside GIFT PPA's Plaso | Expected on Ubuntu: the archive's `xmount` and GIFT's `libewf` conflict. `ewfmount` and `qemu-img` cover Atlas's own tools; to build `xmount` from source anyway, see `docs/xmount-manual-install.md` |
| Not on Debian/Ubuntu | `install.sh` refuses to run automated — see `docs/other-distros.md` |

More detail: root `README.md`, `docs/try-it-out.md`, `docs/dashboard.md`, `docs/docker.md`.
