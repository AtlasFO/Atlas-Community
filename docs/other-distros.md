# Running Atlas on RHEL/Fedora/other non-Debian distros

**This is not automated and not officially supported.** `install.sh`
refuses to run on anything outside the Debian/Ubuntu family — specifically
because every apt package name in it has been chosen and hardened against
Ubuntu 24.04 and Debian 12, and several of those
packages don't exist, are named differently, or come from third-party
repos on RHEL-family systems.
Getting Atlas running here is a manual, DIY effort. This page is a starting
point to save you the initial research, not a guarantee that any of it is
current or complete — verify everything against your actual system.

If you get a working RHEL/Fedora path together, a PR extending `install.sh`
with a real `dnf`/`yum` branch (mirroring the existing apt logic) would be
genuinely useful — this page exists partly so that work has somewhere to
start from.

## What doesn't need a distro-specific path at all

These are already the same regardless of OS, since they never go through
`APT_PACKAGES`:

- **Volatility 3** — `pip install volatility3` into a venv, same as
  everywhere else.
- **Plaso** — `pip install plaso` (the GIFT PPA `install.sh` uses on Ubuntu
  doesn't apply; pip is already the fallback path there too, so this is the
  same "less tested but works" path Debian gets).
- **chainsaw, RegRipper, INDXParse.py** — all fetched directly from GitHub
  (a release binary, a `git clone`, and a `pip install` of a pinned commit
  into the venv), not packaged. Copy the
  corresponding block out of `install.sh` almost verbatim — the only Ubuntu-
  specific things in those blocks are the `sudo`/root handling, which is
  already distro-agnostic bash.
- **EZ Tools** — downloaded .NET zips from `download.mikestammer.com`, needs
  a .NET 9 runtime (Microsoft publishes RHEL/Fedora packages for this
  directly — see Microsoft's own `dotnet-install` docs).
- **Python dependencies** (`requirements.txt`/`requirements-dev.txt`) — pure
  pip, works the same everywhere Python 3.11+ and a C toolchain exist.

## The apt → dnf/yum mapping

| apt package (Debian/Ubuntu) | RHEL/Fedora equivalent | Confidence |
|---|---|---|
| `sleuthkit` | `sleuthkit` (EPEL) | Packaged, should work |
| `ewf-tools` | `libewf-tools` (EPEL) | Packaged, should work |
| `foremost` | `foremost` (EPEL) | Packaged, should work |
| `testdisk` | `testdisk` (EPEL) | Packaged, should work |
| `clamav` | `clamav` (EPEL) | Packaged, should work |
| `libimage-exiftool-perl` | `perl-Image-ExifTool` (EPEL) | Packaged, should work |
| `hashdeep` | `hashdeep` (EPEL) | Packaged, should work |
| `qemu-utils` | `qemu-img` (base repos) | Packaged, should work |
| `binwalk` | `binwalk` (EPEL, sometimes stale) | Verify version |
| `xmount` | — | **Not in EPEL** as of this writing; may need a source build |
| `ssdeep` | `ssdeep` (EPEL) | Packaged, should work |
| `scalpel` | — | **Not in EPEL**; source build from the upstream project |
| `bulk-extractor` | — | **Not reliably packaged anywhere**; same caveat `install.sh` already carries on Ubuntu/Debian, just more likely to bite here |
| `pff-tools`, `pst-utils` | libpff/libpst equivalents exist but package names/splits differ | Needs verification per distro |
| `tcpxtract` | — | Not commonly packaged; source build |
| `libparse-win32registry-perl` | Not packaged; install via `cpan Parse::Win32Registry` | RegRipper's Perl dependency — needed for `misc.regripper_hive` |
| `unzip`, `git`, `curl` | same names, base repos | Packaged, should work |

Best-effort/optional extras (`whois`, `upx`, `tshark`, `radare2`, `zeek`,
`suricata`) are all individually packaged for RHEL/Fedora under the same or
similar names, typically via EPEL or the project's own repo (Zeek and
Suricata both publish RHEL/CentOS/Fedora repos directly).

## What this means in practice

Core disk/filesystem forensics (Sleuth Kit, EWF, memory forensics via
Volatility 3, timeline via Plaso) should come together without too much
trouble — those paths are either already distro-agnostic or well-packaged in
EPEL. File carving (`bulk_extractor`, `scalpel`) and a handful of smaller
utilities (`xmount`, `tcpxtract`) are the parts most likely to need a manual
source build. Everything in `tools/*.py` degrades gracefully when its binary
is missing (`shutil.which()` checks throughout), so a partial toolchain
doesn't break the
rest of Atlas; it just means the tools backed by the missing binary report
themselves unavailable until you fill the gap.

The passwordless-sudo step (`bin/atlas-sudoers`, `share/atlas-sudoers.in`)
is plain `sudoers.d` syntax and works identically on any distro using
standard `sudo` — no changes needed there.
