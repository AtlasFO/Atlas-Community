# Try It Out

*Two ways to evaluate Atlas.*

Two ways to evaluate Atlas, shortest first:

- **[Path A — Browse a finished investigation](#path-a--browse-a-finished-investigation)** (~2 min, **no evidence, no API key**). Install, launch the dashboard, and read a completed run's trace and report. This is the fastest way to see what Atlas produces and how every finding links back to the tool call that produced it.
- **[Path B — Run a fresh investigation](#path-b--run-a-fresh-investigation)** (needs evidence and a connected model). Drive Atlas end-to-end on a real image and compare your run against the committed one.

> **Full-quality runs need a connected model.** Any OpenAI-compatible backend powers the analyst, the `reason.*` adversarial reviewer and the `dair.*` phase director; `bin/atlas provider setup` connects one and tests it. Path A needs no model (you are reading a finished run); Path B does. See [docs/llm.md](llm.md).

---

## Prerequisites

> **Reference platform.** This walkthrough was run on the **SANS SIFT Workstation VMware image, release 2026-04-22 (Ubuntu 24.04.4 LTS, x86-64, `python3` 3.12)**. Other SIFT releases work, but package versions (notably the `pythonX.Y-venv` the installer needs) track the base Ubuntu — see [Troubleshooting](#troubleshooting).

| Need | For | Notes |
|------|-----|-------|
| **SANS SIFT Workstation** (Ubuntu 24.04 x86-64) | Path B (the forensic tools) | Path A only needs Python 3.11+ and a browser. [Download](https://www.sans.org/tools/sift-workstation/) |
| **Python 3.11+** | Both | Included in SIFT |
| **.NET 9 runtime** (`dotnet-runtime-9.0`) | Path B — the `ez.*` Windows parsers | Included in SIFT. On a bare host: `sudo apt-get install -y dotnet-runtime-9.0`. The SDK is *not* required, and missing .NET is not fatal — `install.sh` warns and the rest of Atlas works. |
| **A model** | Path B (full-quality) | Any OpenAI-compatible backend powers the analyst + `reason.*` + `dair.*`; connect it with `bin/atlas provider setup`. |

---

## Install (both paths)

```bash
git clone https://github.com/AtlasFO/Atlas-Community.git ~/Atlas
cd ~/Atlas
./install.sh
```

`install.sh` is idempotent — safe to re-run. It will:

- Verify `python3`, and probe for a .NET 9 runtime (`dotnet --list-runtimes`)
- Enable the `universe` apt component if missing, then install the forensic packages below and chainsaw
- Download the EZ Tools into `/opt/zimmermantools` (skipped if already present) and normalize their permissions so every analyst on a shared box can read them
- Create a venv under `Atlas/.venv` (symlinked as `~/.venv`) and install Python dependencies
- Install the dashboard launcher (`atlas-dashboard` → `/usr/local/bin`)
- Install MITRE tables into `~/cases/.common/`; leave bundled studies in `demo-cases/` / `benchmarks/`
- Smoke-check `hub/playbook` assembly for `bin/atlas`
- Run a quick post-install check (seconds); the full test suite runs only with `--with-full-tests`

When it finishes you have a working install and finished investigations to browse (Path A).

### System forensic packages

`install.sh` installs these from apt automatically. On a full SIFT Workstation most are already present; on a leaner base — or if the installer prints a `!` warning about one — install them by hand. The `universe` component must be enabled first (these packages live there):

```bash
sudo add-apt-repository -y universe
sudo apt-get update
sudo apt-get install -y pff-tools pst-utils binwalk tcpxtract sleuthkit ewf-tools
```

| apt package | Binary | Atlas tools |
|-------------|--------|-------------|
| `pff-tools` | `pffexport` | `misc.pff_export` (PST/OST email) |
| `pst-utils` | `readpst` | `misc.readpst_extract` (PST→mbox) — **not** `libpst-utils` |
| `sleuthkit` | `fls`, `icat`, `mmls`, … | `tsk.*` |
| `ewf-tools` | `ewfmount`, `ewfverify` | `ewf.*`, `img.*` (E01) |
| `tcpxtract` | `tcpxtract` | `net.tcpxtract_streams` |
| `binwalk` | `binwalk` | embedded carving |

chainsaw (Sigma over EVTX, `misc.chainsaw_hunt`) is fetched from its GitHub release into `/usr/local/bin` and is optional — Atlas runs without it. Verify the apt set landed:

```bash
for b in pffexport readpst fls ewfmount tcpxtract; do command -v "$b" || echo "MISSING: $b"; done
```

---

## Path A — Browse a finished investigation

No evidence, no API key. You are reading a run Atlas already completed.

**1. Launch the dashboard** on the demo studies:

```bash
cd ~/Atlas
./dashboard.sh --demo          # http://127.0.0.1:8765  (demo-cases/)
# ./dashboard.sh --port 9090   # if 8765 is taken
```

**2. Sign in and open RHINO-HUNT.** The first visit creates your admin account. Then pick **RHINO-HUNT** from the case list: a complete run on the public DFRWS 2005 "Rhino Hunt" challenge, a reformatted USB key and three network captures. Every tab reads the same run:

| Tab | What you see |
|-----|--------------|
| **Overview** | The run at a glance: questions answered, findings by confidence, indicators, response items, and every finding placed along the run |
| **Questions** | Each investigation question with its answer and the claims and evidence behind it |
| **Case Findings** | Every belief by host and confidence, with its evidence references and earlier versions |
| **IoCs** | The typed indicators, and whether each was searched for |
| **Response** | What the case tells the responder to do, ordered by urgency and evidence |
| **Process** | The run in time (phases, director rulings, reasoning gates, tool calls, failures, findings), then every entry with its arguments and result |
| **Report** | The finished reports, as Markdown, HTML or PDF |
| **Brief** | The case file Atlas was given |

**3. Read the report** it produced:

```
~/Atlas/demo-cases/rhino-hunt/reports/estate_report.md
```

**What to look for** (this is Atlas in miniature):

- **Audit trail**: open a question, pick one of its supporting claims and follow it into Case Findings; in Process, a tool call that produced findings says so, and a finding's evidence references lead back to the calls behind it. Nothing is asserted without a traceable source.
- **Adversarial review**: the reasoning gates in the Process timeline, and the self-corrections counted under Findings, where Atlas revised a claim that did not survive review (Case Findings marks a revised belief with its version).
- **Confidence tiers**: CONFIRMED, LIKELY, SUSPECTED and UNCONFIRMED stated explicitly. The two steganography carriers, for example, stay SUSPECTED because the installed extractors could not read their payloads.

NITROBA-2008 ships as a case brief you can run yourself (Path B). [docs/datasets.md](datasets.md) lists it with more public datasets to try and where their evidence comes from.

---

## Path B — Run a fresh investigation

This drives Atlas end-to-end. It needs the evidence (not committed — it's large and better fetched from source) and a connected model.

**1. Connect a model**, unless `install.sh` already did:

```bash
bin/atlas provider setup   # the Telekom LLM Hub, OpenAI, a local server or any OpenAI-compatible endpoint
bin/atlas doctor           # which backend and model each role uses
```

> Optional: `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` add IOC corroboration but never block a run. Without a model, a full-quality investigation cannot run.

**2. Get the evidence.** Each case in [docs/datasets.md](datasets.md) links to its authoritative source. The bundled NITROBA-2008 brief already has its evidence path filled in, so the simplest fresh run is to drop the capture into it:

```bash
# Example: NITROBA-2008 (a small ~54 MB PCAP — the lightest fresh run)
#   source: https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/
mkdir -p ~/Atlas/demo-cases/nitroba/evidence
cp /path/to/nitroba.pcap ~/Atlas/demo-cases/nitroba/evidence/
```

Or start a brand-new case from the template:

```bash
cp -r ~/Atlas/case-template ~/cases/<CASE_ID>
# edit ~/cases/<CASE_ID>/CASE.md — evidence paths, hostnames, the case question
#   (no question? Atlas investigates "What happened on the Host(s)?")
cp /path/to/image.E01 ~/cases/<CASE_ID>/evidence/
```

**3. Run it.**

```bash
cd ~/Atlas
bin/atlas run --case ~/cases/<CASE_ID>            # -q "..." overrides CASE.md for one run
```

Atlas runs autonomously — no confirmation between steps. It prints the **live dashboard URL** for this run at the start, so you can watch the trace fill in real time (`./dashboard.sh` in another terminal if it isn't already up). Want it graded automatically afterward? Use `bin/atlas train --case ~/cases/<CASE_ID> -q "..."` instead — it runs from a clean slate, then an independent reviewer writes `reports/<CASE_ID>_run_review.md`.

> **All `bin/atlas` commands, explained for new users** — which command when, worked examples, exit codes, and running the forensic tools on a remote SIFT VM (`--remote`): see the **[CLI guide](cli.md)**.

**4. Read the output.**

```
~/cases/<CASE_ID>/reports/<CASE_ID>_investigation_report.md   ← analyst report
~/cases/<CASE_ID>/reports/<CASE_ID>_trace.{json,md}           ← exported audit trail (component #8)
~/cases/<CASE_ID>/analysis/<CASE_ID>_trace.json               ← live trace (dashboard input)
```

**5. (Optional) Score it.** `atlas train --case ~/cases/<CASE_ID>` runs the case afresh and has an independent reviewer grade the run; a case with a machine-readable answer key (`ground_truth.json` at its root) is also scored against it. [docs/datasets.md](datasets.md) links the published answers of the public datasets.

---

## Verifying the install worked

```bash
# Hub config resolves
bin/atlas doctor

# Playbook assembles
python -m agent.playbook -o /tmp/atlas-playbook.md

# The full test suite passes (install.sh runs it only with --with-full-tests)
cd ~/Atlas && source ~/.venv/bin/activate && pytest -q

# The dashboard serves the bundled cases
./dashboard.sh           # then open http://127.0.0.1:8765
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `reason.*` / `dair.*` errors about missing URL/key | No model connected for that role. Run `bin/atlas provider setup`, then `bin/atlas doctor`. |
| Dashboard shows no cases | Default is production `~/cases`. For demos use `./dashboard.sh --demo`. |
| Port 8765 in use | `./dashboard.sh --port 9090` |
| Dashboard only on 127.0.0.1 | Bind is localhost by default. Re-run `./install.sh --with-dashboard-lan` (HTTPS on the LAN) and open `https://<host-ip>:8765`. First visit creates the admin. |
| Browser warns about the certificate | Expected for the generated self-signed cert. Drop an org cert at `/etc/atlas/dashboard/tls.crt` + `tls.key` (key mode 0600) and `sudo systemctl restart atlas-dashboard`. |
| Volatility plugin times out / `-1` exit | Symbols not cached — run `vol.symbol_check` on the image first; raise `ATLAS_VOL_TIMEOUT` in `.env` on slow hardware. |
| `ez.*` tools fail: "The framework 'Microsoft.NETCore.App', version '9.x' was not found" | No .NET 9 runtime. Ubuntu 24.04+: `sudo add-apt-repository ppa:dotnet/backports && sudo apt-get install -y dotnet-runtime-9.0`. Ubuntu 22.04 / Debian: enable `packages.microsoft.com` first (see `install.sh`), then `sudo apt-get install -y dotnet-runtime-9.0`. Either way, re-run `./install.sh` afterward. |
| `ez.*` tools fail with `PermissionError` on a dll, but only for *some* users | `/opt/zimmermantools` subdirs are not world-traversable (a `774` extraction). Re-run `./install.sh`, or `sudo chmod -R a+rX /opt/zimmermantools`. |
| `ez.*` tools report the dll is missing | `/opt/zimmermantools` was never populated (non-SIFT host). Re-run `./install.sh` with network access; it downloads them. |
| `Unable to locate package <pst-utils/pff-tools/tcpxtract>` | `universe` apt component not enabled, or apt index stale on a fresh image. `sudo add-apt-repository -y universe && sudo apt-get update`, then re-run `./install.sh`. (The package is `pst-utils`, never `libpst-utils`.) |
| `misc.readpst_extract` / `misc.pff_export` fail with "not installed" | `pst-utils` / `pff-tools` missing — see [System forensic packages](#system-forensic-packages). |
| venv step fails: `ensurepip is not available` | The venv package matching your `python3` isn't installed — **the SIFT base does not ship it** (SIFT's `python3` is 3.12). Install the **version-matched** package, not just the metapackage: `sudo apt-get install -y python3.12-venv python3-pip` (replace `3.12` with `python3 --version`), then `rm -rf ~/.venv` and re-run `./install.sh`. (`install.sh` now auto-installs the matching `pythonX.Y-venv` and retries.) |

---

For the architecture behind what you're running, see [architecture.md](architecture.md).
