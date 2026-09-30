#!/usr/bin/env bash
# Atlas install script.
#
# Hardened primary targets: Ubuntu 24.04 (noble) and Debian 12 (bookworm).
# Ubuntu 22.04 (jammy) ships python3 3.10, below the 3.11 the Python check
# requires, so it only works with a newer python3 installed first. 24.04 is
# the tested/documented default, matching the SIFT Workstation itself
# (teamdfir/sift-saltstack supports 22.04 and 24.04; 24.04 is current).
# Other Debian/Ubuntu releases are attempted best-effort. A SIFT Workstation
# (https://www.sans.org/tools/sift-workstation/) or Protocol SIFT
# (https://github.com/teamdfir/protocol-sift) already has most of what this
# script provisions, so running it there just fills in the small remaining
# gaps — no separate "SIFT mode" needed, every step below already checks
# whether its target is present before doing anything.
set -euo pipefail

ATLAS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Venv lives in the repo; ~/.venv is a symlink for tools that expect $HOME.
VENV_DIR="$ATLAS_DIR/.venv"

# Defensive: re-assert the executable bit on every script Atlas invokes
# directly, regardless of how this checkout was obtained. git preserves it
# correctly (these are all 100755 in the repo), but downloading a GitHub
# ZIP ("Download ZIP" -> a folder like Atlas-Community-main, as opposed to
# `git clone`) frequently drops it depending on the unzip tool used, and
# the install then fails with "Permission denied" on bin/atlas. An
# explicit list, not a `chmod +x bin/*`
# wildcard: bin/atlas-alert-waiter.py is a module, not a command, and is
# intentionally not executable.
for f in bin/atlas bin/atlas-secret bin/atlas-sudoers bin/atlas-smb-share \
         bin/atlas-dashboard bin/atlas-dev dashboard.sh uninstall.sh \
         .githooks/pre-commit .githooks/pre-push; do
    [ -f "$ATLAS_DIR/$f" ] && chmod +x "$ATLAS_DIR/$f"
done

# Every pinned external-tool version lives in one file — see
# install-versions.env's own header for why, and the rollback/freshness-check
# story that depends on it staying the single source of truth.
# shellcheck source=install-versions.env
source "$ATLAS_DIR/install-versions.env"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
info() { echo -e "${CYAN}  ·${NC} $*"; }
# Every warn() also lands in INSTALL_WARNINGS — yellow in the live stream is
# the right color for "degraded, not fatal," but a single yellow line hundreds
# of lines above the end of the install log is easy to miss. The final summary
# reprints every one of these in red right before "Atlas is ready" — impossible
# to scroll past — without changing what color means during the live run.
INSTALL_WARNINGS=()
warn() { echo -e "${YELLOW}  !${NC} $*"; INSTALL_WARNINGS+=("$*"); }
fail() { echo -e "${RED}  ✗${NC} $*"; exit 1; }
step() { echo -e "\n${GREEN}▶${NC} $*"; }

# ── 0. Flags / environment ────────────────────────────────────────────────────

ASSUME_YES="${ATLAS_INSTALL_YES:-0}"
WITH_NETWORK_TOOLS="${ATLAS_INSTALL_NETWORK_TOOLS:-0}"
WITH_NETWORK_SHARE="${ATLAS_INSTALL_NETWORK_SHARE:-0}"
WITH_DASHBOARD_SERVICE="${ATLAS_INSTALL_DASHBOARD_SERVICE:-0}"
WITH_DASHBOARD_LAN="${ATLAS_INSTALL_DASHBOARD_LAN:-0}"
WITH_FULL_TESTS="${ATLAS_INSTALL_FULL_TESTS:-0}"

usage() {
    cat <<EOF
Atlas installer

Usage: ./install.sh [options]

  -y, --yes               Non-interactive: accept every prompt's default.
                           Required for unattended/Docker builds (no TTY).
  --with-network-tools      Attempt optional zeek/suricata network monitoring
                           tools (skipped by default; heavier, own repos).
  --with-network-share      Set up an SMB share so evidence can be copied in
                           from Windows without SSH (skipped by default —
                           installs samba and opens ports 139/445 on
                           whatever interface you allow through your
                           firewall; see docs/network-share.md).
  --with-dashboard-service  Enable the dashboard systemd unit so it starts
                           on boot (skipped by default).
  --with-dashboard-lan      Bind the dashboard on 0.0.0.0 (HTTPS) so it is
                           reachable on the LAN, not only 127.0.0.1
                           (skipped by default).
  --with-full-tests         Also run the full developer test suite at the end
                           (skipped by default — several minutes on a
                           workstation, 30 minutes or more on a small VM).
                           The quick post-install check always runs.
  -h, --help               This help.

Env var equivalents (useful for Dockerfiles): ATLAS_INSTALL_YES=1,
ATLAS_INSTALL_NETWORK_TOOLS=1, ATLAS_INSTALL_NETWORK_SHARE=1,
ATLAS_INSTALL_DASHBOARD_SERVICE=1, ATLAS_INSTALL_DASHBOARD_LAN=1,
ATLAS_INSTALL_FULL_TESTS=1.
EOF
}

for arg in "$@"; do
    case "$arg" in
        -y|--yes|--non-interactive) ASSUME_YES=1 ;;
        --with-network-tools) WITH_NETWORK_TOOLS=1 ;;
        --with-network-share) WITH_NETWORK_SHARE=1 ;;
        --with-dashboard-service) WITH_DASHBOARD_SERVICE=1 ;;
        --with-dashboard-lan) WITH_DASHBOARD_LAN=1 ;;
        --with-full-tests) WITH_FULL_TESTS=1 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "Unknown option: $arg (see --help)" ;;
    esac
done

# Never let a package postinst script pop a debconf dialog and hang a
# non-interactive/Docker build. Safe to set unconditionally — it only
# changes how apt behaves when it would otherwise prompt.
export DEBIAN_FRONTEND=noninteractive

ask_yn() {
    # ask_yn "question" default(y|n) -> sets REPLY_YN=0/1
    local prompt="$1" default="${2:-n}" reply suffix
    if [ "$ASSUME_YES" = 1 ] || [ ! -t 0 ]; then
        REPLY_YN=0
        [ "$default" = y ] && REPLY_YN=1
        return 0
    fi
    suffix="[y/N]"; [ "$default" = y ] && suffix="[Y/n]"
    read -r -p "  ? $prompt $suffix " reply || reply=""
    reply="${reply:-$default}"
    case "$reply" in
        y|Y|yes|Yes) REPLY_YN=1 ;;
        *) REPLY_YN=0 ;;
    esac
}

echo ""
echo "  Atlas — Autonomous DFIR agent for malware analysis and rogue-actor attribution"
echo "  ==================================================================="
echo "  Installing into: $ATLAS_DIR"
echo ""

# ── 0b. Environment detection ─────────────────────────────────────────────────

step "Detecting environment"

# OS tier: hardened (noble/bookworm) / best-effort apt family / unsupported.
OS_ID="" OS_VERSION="" OS_TIER="unsupported"
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_VERSION="${VERSION_ID:-}"
fi
case "$OS_ID" in
    ubuntu)
        OS_TIER="best-effort"
        [ "$OS_VERSION" = "24.04" ] && OS_TIER="hardened"
        ;;
    debian)
        OS_TIER="best-effort"
        [ "$OS_VERSION" = "12" ] && OS_TIER="hardened"
        ;;
    *) OS_TIER="unsupported" ;;
esac

if [ "$OS_TIER" = "unsupported" ]; then
    fail "Unsupported OS ($OS_ID ${OS_VERSION:-unknown}). This installer automates Debian/Ubuntu only. See docs/other-distros.md for a manual, unsupported RHEL/Fedora/etc. starting point — adapting it is on you."
elif [ "$OS_TIER" = "hardened" ]; then
    ok "OS: $OS_ID $OS_VERSION (hardened target)"
else
    warn "OS: $OS_ID $OS_VERSION — not the hardened baseline (Ubuntu 24.04 / Debian 12). Should mostly work since package names are stable across nearby releases; if a step below fails, that's the first thing to suspect."
fi

# Root vs sudo. Shadow `sudo` as a no-op passthrough when already root
# (the common case inside a container build) instead of touching every
# call site below.
if [ "$(id -u)" = 0 ]; then
    RUNNING_AS_ROOT=1
    sudo() { "$@"; }
    export -f sudo   # bin/atlas-sudoers runs as a child script — needs the shadow too
    ok "Running as root — sudo calls below run directly"
else
    RUNNING_AS_ROOT=0
    command -v sudo >/dev/null 2>&1 || fail "Not running as root and 'sudo' is not installed. Install sudo, or re-run this script as root (e.g. inside a container build)."
    ok "Running as $(whoami) — will use sudo for privileged steps"
fi

# Container detection — informs the sudoers step and the loop-device probe.
# systemd-detect-virt first: it uses several signals (not just cgroup path
# parsing) and is what actually gets this right under cgroup v2, where
# /proc/1/cgroup collapses to a bare "0::/" with no technology name in it at
# all — the old cgroup-grep-only check silently missed every LXC container
# on cgroup v2 and fell through to the wrong, less actionable
# warning below.
IN_CONTAINER=0
CONTAINER_TECH=""
if command -v systemd-detect-virt >/dev/null 2>&1; then
    CONTAINER_TECH="$(systemd-detect-virt --container 2>/dev/null || true)"
    [ -n "$CONTAINER_TECH" ] && [ "$CONTAINER_TECH" != "none" ] && IN_CONTAINER=1
fi
if [ "$IN_CONTAINER" != 1 ] && { [ -f /.dockerenv ] || [ -f /run/.containerenv ] \
   || grep -qE 'docker|containerd|lxc' /proc/1/cgroup 2>/dev/null; }; then
    IN_CONTAINER=1
    [ -z "$CONTAINER_TECH" ] && CONTAINER_TECH="container"
fi
[ "$IN_CONTAINER" = 1 ] && ok "Detected: running inside a container ($CONTAINER_TECH)"

# Loop-device / mount capability — the #1 way a container install silently
# breaks disk-image tools (carving, imaging, TSK on E01/dd images) later.
# Surface it now, not on the first case run.
LOOP_OK=0
if [ -e /dev/loop-control ] && { [ -w /dev/loop-control ] || [ "$RUNNING_AS_ROOT" = 1 ]; }; then
    LOOP_OK=1
elif command -v losetup >/dev/null 2>&1 && sudo losetup -f >/dev/null 2>&1; then
    LOOP_OK=1
fi
if [ "$LOOP_OK" = 1 ]; then
    ok "Loop-device support available (image mount/carve tools will work)"
elif [ "$CONTAINER_TECH" = "lxc" ]; then
    warn "No usable loop-device support — disk-image mount/carve tools (tsk.*, img.*, carving.*) will fail. LXC containers (Proxmox included) share the host kernel: the 'loop' module must be loaded on the PROXMOX HOST (not in here), and /dev/loop-control + /dev/loopN must be passed through in the container config. See docs/proxmox-lxc.md for the exact host-side steps — a plain in-container 'modprobe loop' will not fix this."
elif [ "$IN_CONTAINER" = 1 ]; then
    warn "No usable loop-device support — disk-image mount/carve tools (tsk.*, img.*, carving.*) will fail. Re-create this container with --privileged, or minimally --cap-add SYS_ADMIN --device /dev/loop-control (plus the /dev/loopN nodes you need)."
else
    warn "No usable loop-device support detected — disk-image mount/carve tools will fail. Check that the 'loop' kernel module is loaded (modprobe loop) and /dev/loop-control exists."
fi

# ── Install manifest — what Atlas's installs added, so uninstall.sh can
# remove exactly that and nothing the system already had. The file is
# cumulative: a rerun's steps find their tools present and add nothing, so
# each run merges what it added into what earlier runs recorded. ─────────────
MANIFEST_NEW_PKGS=()
MANIFEST_PATHS=()       # "type:path" pairs, e.g. "dir:/opt/regripper"
MANIFEST_FORGET_PATHS=() # paths this run removed that an earlier run recorded
MANIFEST_FLAG_GIFT_PPA=0
MANIFEST_FLAG_ZEEK_REPO=0
MANIFEST_FLAG_SMB_SHARE=0
MANIFEST_FLAG_DASHBOARD_SERVICE=0
MANIFEST_FLAG_DOTNET_PPA=0
MANIFEST_SUDOERS_FILE=""
MANIFEST_WRITTEN=0

record_pkgs() { local p; for p in "$@"; do MANIFEST_NEW_PKGS+=("$p"); done; }
record_path() { MANIFEST_PATHS+=("$1:$2"); }  # type, path
# forget_path <path> — the path is gone: earlier runs' record of it leaves the
# manifest, and so does this run's so far; a later record_path re-adds it.
forget_path() {
    local e kept=()
    for e in "${MANIFEST_PATHS[@]:-}"; do
        [ -n "$e" ] && [ "${e#*:}" != "$1" ] && kept+=("$e")
    done
    if [ "${#kept[@]}" -gt 0 ]; then MANIFEST_PATHS=("${kept[@]}"); else MANIFEST_PATHS=(); fi
    MANIFEST_FORGET_PATHS+=("$1")
}

# pkg_installed <pkg> — dpkg reports the package installed. `dpkg -s` also
# succeeds for a package removed with its conffiles kept ("rc"); the status
# abbreviation does not. A multi-arch package prints one "ii " per
# architecture, hence the prefix match.
pkg_installed() {
    local st
    st=$(dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null) || st=""
    case "$st" in "ii "*) return 0 ;; esac
    return 1
}

# apt_install_new <pkg>... — installs the packages that are not installed and
# records only those: a package that was already there must not reach the
# manifest, or `uninstall.sh --purge-system-packages` would remove something
# that predates Atlas. Returns apt-get's status, 0 when nothing was missing.
apt_install_new() {
    local p missing=()
    for p in "$@"; do
        pkg_installed "$p" || missing+=("$p")
    done
    [ "${#missing[@]}" -eq 0 ] && return 0
    sudo apt-get install -y "${missing[@]}" || return 1
    record_pkgs "${missing[@]}"
}

# add_apt_repo_with_key <key-url> <list-dest> <key-dest> <repo-line>
#
# Fetches and dearmors the signing key to a scratch file *first* and only
# writes anything under /etc/apt once that key is verified non-empty — the
# reverse order (list first, key second, as a single `&&` chain) leaves a
# window under `set -e -o pipefail` where a transient curl failure mid-chain
# still leaves the just-written .list file on disk with no valid key behind
# it, and no manifest flag set to let uninstall.sh find it again. Any
# third-party apt repo this installer adds should go through this helper
# rather than reimplementing the tee+gpg pipeline inline, so this ordering
# mistake can't recur per-repo. Echoes nothing; returns 0 on success (both
# files written) or 1 (nothing written — caller's manifest flag stays 0).
add_apt_repo_with_key() {
    local key_url="$1" list_dest="$2" key_dest="$3" repo_line="$4"
    local key_tmp
    key_tmp="$(mktemp)"
    if ! curl -fsSL "$key_url" 2>/dev/null | gpg --dearmor >"$key_tmp" 2>/dev/null || [ ! -s "$key_tmp" ]; then
        rm -f "$key_tmp"
        return 1
    fi
    if echo "$repo_line" | sudo tee "$list_dest" &>/dev/null \
        && sudo install -m 0644 "$key_tmp" "$key_dest" &>/dev/null; then
        rm -f "$key_tmp"
        return 0
    fi
    # Partial write (e.g. .list succeeded, key install failed) — leave
    # nothing behind for uninstall.sh to miss.
    sudo rm -f "$list_dest" "$key_dest"
    rm -f "$key_tmp"
    return 1
}

write_manifest() {
    local out="$ATLAS_DIR/.install-manifest.json" rc=0 stamp
    stamp="$(date +%Y%m%dT%H%M%S)"
    ATLAS_MANIFEST_OUT="$out" \
    ATLAS_MANIFEST_STAMP="$stamp" \
    ATLAS_MANIFEST_PKGS="$(printf '%s\n' "${MANIFEST_NEW_PKGS[@]:-}")" \
    ATLAS_MANIFEST_PATHS="$(printf '%s\n' "${MANIFEST_PATHS[@]:-}")" \
    ATLAS_MANIFEST_FORGET="$(printf '%s\n' "${MANIFEST_FORGET_PATHS[@]:-}")" \
    ATLAS_MANIFEST_GIFT_PPA="$MANIFEST_FLAG_GIFT_PPA" \
    ATLAS_MANIFEST_ZEEK_REPO="$MANIFEST_FLAG_ZEEK_REPO" \
    ATLAS_MANIFEST_SMB_SHARE="$MANIFEST_FLAG_SMB_SHARE" \
    ATLAS_MANIFEST_DASHBOARD_SERVICE="$MANIFEST_FLAG_DASHBOARD_SERVICE" \
    ATLAS_MANIFEST_DOTNET_PPA="$MANIFEST_FLAG_DOTNET_PPA" \
    ATLAS_MANIFEST_SUDOERS="$MANIFEST_SUDOERS_FILE" \
    ATLAS_MANIFEST_VENV="$VENV_DIR" \
    python3 - <<'PYEOF' || rc=$?
import json, os, shutil, time

out = os.environ["ATLAS_MANIFEST_OUT"]
now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
FLAGS = (("gift_ppa_added", "GIFT_PPA"), ("zeek_repo_added", "ZEEK_REPO"),
         ("smb_share_enabled", "SMB_SHARE"),
         ("dashboard_service_enabled", "DASHBOARD_SERVICE"),
         ("dotnet_ppa_added", "DOTNET_PPA"))


def lines(key):
    return [v for v in os.environ.get(key, "").splitlines() if v]


def well_formed(m):
    """The shape uninstall.sh reads. A field of another type (a hand-edited
    string where a list belongs) would corrupt the merge silently."""
    pkgs, paths = m.get("new_apt_packages", []), m.get("installed_paths", [])
    return (isinstance(pkgs, list) and all(isinstance(p, str) for p in pkgs)
            and isinstance(paths, list)
            and all(isinstance(p, dict) and isinstance(p.get("type"), str)
                    and isinstance(p.get("path"), str) for p in paths)
            and all(isinstance(m.get(key, False), bool) for key, _ in FLAGS)
            and isinstance(m.get("sudoers_file", ""), str)
            and isinstance(m.get("installed_at", ""), str))


# What earlier runs recorded. A file that does not parse, or holds other
# types, is kept beside the new one rather than overwritten: it may be the
# only record of them.
previous, unreadable = {}, False
if os.path.exists(out):
    try:
        with open(out, encoding="utf-8") as f:
            previous = json.load(f)
        if not isinstance(previous, dict) or not well_formed(previous):
            raise ValueError("unexpected shape")
    except (OSError, ValueError):
        kept, n = f"{out}.unreadable-{os.environ['ATLAS_MANIFEST_STAMP']}", 1
        while os.path.exists(kept):  # an earlier copy is never overwritten
            kept, n = f"{out}.unreadable-{os.environ['ATLAS_MANIFEST_STAMP']}.{n}", n + 1
        shutil.copyfile(out, kept)
        previous, unreadable = {}, True

# Earlier runs' paths first, then this run's; forget_path already removed a
# gone path from this run's list, and here from the earlier ones.
forget = set(lines("ATLAS_MANIFEST_FORGET"))
candidates = [p for p in previous.get("installed_paths", []) if p["path"] not in forget]
for entry in lines("ATLAS_MANIFEST_PATHS"):
    kind, _, path = entry.partition(":")
    candidates.append({"type": kind, "path": path})
paths, seen = [], set()
for entry in candidates:
    key = (entry["type"], entry["path"])
    if key[1] and key not in seen:
        seen.add(key)
        paths.append({"type": key[0], "path": key[1]})

manifest = {
    "installed_at": previous.get("installed_at") or now,
    "updated_at": now,
    "atlas_dir": os.path.dirname(out),
    "venv_dir": os.environ.get("ATLAS_MANIFEST_VENV", ""),
    "new_apt_packages": sorted(set(previous.get("new_apt_packages", []))
                               | set(lines("ATLAS_MANIFEST_PKGS"))),
    "installed_paths": paths,
}
# A flag any run set stays set: what it stands for is still on the system.
for key, env in FLAGS:
    manifest[key] = previous.get(key, False) or os.environ.get(f"ATLAS_MANIFEST_{env}") == "1"
manifest["sudoers_file"] = (os.environ.get("ATLAS_MANIFEST_SUDOERS")
                            or previous.get("sudoers_file", ""))

# Written beside the target with the process umask, so a manifest written by
# `sudo ./install.sh` stays readable for the analyst's ./uninstall.sh.
tmp = out + ".tmp"
try:
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    os.replace(tmp, out)
finally:
    if os.path.exists(tmp):
        os.remove(tmp)
raise SystemExit(3 if unreadable else 0)
PYEOF
    case "$rc" in
        0) ok "Install manifest written → $out (uninstall.sh reads this)" ;;
        3) warn "The previous install manifest did not parse or held unexpected types — kept as $out.unreadable-$stamp; $out now lists only what this run added" ;;
        *) warn "Could not write $out (python3 exited $rc) — uninstall.sh will not know what this run added"
           return 1 ;;
    esac
}

# However the script ends, what it installed so far is recorded: a run that
# stops midway (a failed pip step, a fail() in a later check) has already
# changed the system. The normal path writes the manifest at step 7. The
# handler cannot fail, so the script's own exit status survives it.
_manifest_on_exit() {
    [ "$MANIFEST_WRITTEN" = 1 ] && return 0
    MANIFEST_WRITTEN=1
    command -v python3 >/dev/null 2>&1 && { write_manifest || true; }
    return 0
}
trap _manifest_on_exit EXIT

# ── 1. Prerequisites ──────────────────────────────────────────────────────────

step "Checking prerequisites"

if ! command -v python3 &>/dev/null; then
    warn "python3 not found — installing…"
    if sudo apt-get update -qq && sudo apt-get install -y python3 2>/dev/null; then
        record_pkgs python3
        ok "Installed python3"
    else
        fail "Could not install python3 automatically — install it manually (sudo apt-get install -y python3) and re-run."
    fi
fi
PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
[ "$PYTHON_MINOR" -ge 11 ] || fail "Python 3.11+ required (found 3.$PYTHON_MINOR) — Ubuntu 24.04 / Debian 12 ship this by default; an older OS (Ubuntu 22.04 ships 3.10) needs a newer python3 installed manually first."
ok "Python 3.$PYTHON_MINOR"

# EZ Tools ship as framework-dependent .NET 9 builds, so what they need is the
# Microsoft.NETCore.App 9.x *runtime*, not the SDK. Probe --list-runtimes rather
# than --version: `dotnet --version` reports the SDK version and exits 145 on a
# runtime-only box, so checking it falsely demands dotnet-sdk-9.0. A missing
# .NET is not fatal either — only the ez.* Windows parsers use it, so warn and
# carry on (same posture as chainsaw/RegRipper below).
_dotnet9_present() {
    DOTNET_RUNTIME=$(dotnet --list-runtimes 2>/dev/null | awk '$1 == "Microsoft.NETCore.App" && $2 ~ /^9\./ { print $2; exit }')
    [ -n "$DOTNET_RUNTIME" ]
}
DOTNET9_OK=0
if command -v dotnet &>/dev/null && _dotnet9_present; then
    DOTNET9_OK=1
    ok "dotnet runtime Microsoft.NETCore.App $DOTNET_RUNTIME"
else
    # .NET 9 isn't in Ubuntu/Debian's own repos — needs a separate repo
    # added first. Technically fail-open (a failure here doesn't abort the
    # rest of install.sh, and nothing outside the ez.* tools imports dotnet)
    # — but EZ Tools (MFTECmd, RECmd, EvtxECmd, PECmd, ...) are core to
    # Atlas's primary workload (Windows images, KAPE triages), not a nice-
    # to-have, so a failure here must be loud and diagnosable, not a quiet
    # footnote — see the retry + real-error-surfacing below.
    # curl is provisioned by APT_PACKAGES further down, which hasn't run
    # yet at this point in the script — make sure it exists now too rather
    # than let this block fail-open purely on step ordering.
    command -v curl &>/dev/null || sudo apt-get install -y curl ca-certificates &>/dev/null || true

    # EZ Tools are core to Atlas's primary workload (Windows images, KAPE
    # triages), not an optional extra like chainsaw/RegRipper. A silent
    # /dev/null failure here is a real problem for that workload, so: capture
    # the actual apt output instead of discarding it, retry once (transient
    # network/PPA-mirror blips are the common cause — the PPA and package
    # themselves install cleanly on a stock Ubuntu 24.04), and surface the
    # real error, not a guess.
    # What is already installed, so the manifest gets only what this adds.
    DOTNET_PKG_PRESENT=0; pkg_installed dotnet-runtime-9.0 && DOTNET_PKG_PRESENT=1
    MS_PROD_PRESENT=0; pkg_installed packages-microsoft-prod && MS_PROD_PRESENT=1
    DOTNET_INSTALL_LOG="$(mktemp)"
    _install_dotnet9_ubuntu24() {
        # Microsoft's own docs say the
        # packages.microsoft.com repo no longer carries .NET packages for
        # Ubuntu 24.04+ — the documented replacement is this PPA.
        sudo add-apt-repository -y ppa:dotnet/backports \
            && sudo apt-get update -qq \
            && sudo apt-get install -y dotnet-runtime-9.0 \
            && command -v dotnet &>/dev/null && _dotnet9_present
    }
    if [ "$OS_ID" = "ubuntu" ] && [ "${OS_VERSION%%.*}" -ge 24 ] 2>/dev/null; then
        if _install_dotnet9_ubuntu24 &>"$DOTNET_INSTALL_LOG" \
            || _install_dotnet9_ubuntu24 &>"$DOTNET_INSTALL_LOG"; then
            DOTNET9_OK=1
            MANIFEST_FLAG_DOTNET_PPA=1
            [ "$DOTNET_PKG_PRESENT" = 1 ] || record_pkgs dotnet-runtime-9.0
            ok "Installed .NET 9 runtime (Microsoft.NETCore.App $DOTNET_RUNTIME) via ppa:dotnet/backports"
        else
            warn "Could not auto-install .NET 9 via ppa:dotnet/backports after 2 attempts — the ez.* Windows artifact parsers (MFTECmd, RECmd, EvtxECmd, PECmd, ...) will be unavailable. This is core for Windows-image/KAPE analysis, don't skip it. Actual apt error (last 15 lines):"
            tail -15 "$DOTNET_INSTALL_LOG" | sed 's/^/    /'
            echo "  Manual retry: sudo add-apt-repository -y ppa:dotnet/backports && sudo apt-get update && sudo apt-get install -y dotnet-runtime-9.0"
        fi
    else
        # Ubuntu 22.04 / Debian: Microsoft's packages.microsoft.com repo,
        # added via the small config .deb Microsoft themselves document for
        # exactly this, rather than hand-rolling the repo line + signing key.
        MS_DEB_URL="https://packages.microsoft.com/config/${OS_ID}/${OS_VERSION}/packages-microsoft-prod.deb"
        MS_DEB_TMP="$(mktemp -d)"
        _install_dotnet9_msrepo() {
            curl -fsSL "$MS_DEB_URL" -o "$MS_DEB_TMP/packages-microsoft-prod.deb" \
                && sudo dpkg -i "$MS_DEB_TMP/packages-microsoft-prod.deb" \
                && sudo apt-get update -qq \
                && sudo apt-get install -y dotnet-runtime-9.0 \
                && command -v dotnet &>/dev/null && _dotnet9_present
        }
        if _install_dotnet9_msrepo &>"$DOTNET_INSTALL_LOG" \
            || _install_dotnet9_msrepo &>"$DOTNET_INSTALL_LOG"; then
            DOTNET9_OK=1
            # packages-microsoft-prod owns the repo file + signing key it
            # just added, so removing it (via --purge-system-packages)
            # cleans both up — no separate path-tracking needed, unlike
            # zeek's raw tee+gpg add.
            [ "$MS_PROD_PRESENT" = 1 ] || record_pkgs packages-microsoft-prod
            [ "$DOTNET_PKG_PRESENT" = 1 ] || record_pkgs dotnet-runtime-9.0
            ok "Installed .NET 9 runtime (Microsoft.NETCore.App $DOTNET_RUNTIME) via packages.microsoft.com"
        else
            warn "Could not auto-install .NET 9 after 2 attempts (no Microsoft config package for $OS_ID $OS_VERSION, offline, or apt failed) — the ez.* Windows artifact parsers will be unavailable. This is core for Windows-image/KAPE analysis, don't skip it. Actual error (last 15 lines):"
            tail -15 "$DOTNET_INSTALL_LOG" | sed 's/^/    /'
            echo "  Manual retry: enable packages.microsoft.com (see https://learn.microsoft.com/dotnet/core/install/linux-ubuntu) then sudo apt-get install -y dotnet-runtime-9.0"
        fi
        rm -rf "$MS_DEB_TMP"
    fi
    rm -f "$DOTNET_INSTALL_LOG"
fi
ok "Frontend: bin/atlas + T-Systems LLM Hub or a standard LLM API"

# ── 1ab. SIFT Workstation detection (informational banner only) ──────────────
# Every step below already checks whether its own target is present before
# installing anything (dpkg -s / command -v per tool) — that per-tool
# granularity is deliberate and load-bearing: a SIFT host is not guaranteed to
# provide everything (ewf-tools/libbde-utils/libvshadow-utils can fail to
# install on SIFT due to package-name conflicts with SIFT's own older-named
# packages, and per-tool checks are what catches and reports that). So
# detecting SIFT here does NOT skip or change any
# installation step — it only prints a heads-up so the (often very long,
# occasionally noisy) output below makes sense: most of it will legitimately
# say "already present" rather than actually installing anything.
#
# Detection: the `ppa:sift/stable` apt repo is how SIFT itself is provisioned
# (via `cast install teamdfir/sift-saltstack` or the older sift-cli) —
# directly confirmed present in a real SIFT Workstation's apt sources. The
# cast/sift-cli binaries are a secondary signal for a SIFT install that
# hasn't run `apt update` since being provisioned.
SIFT_DETECTED=0
if grep -rq "sift/stable\|teamdfir" /etc/apt/sources.list.d/ 2>/dev/null \
        || command -v cast &>/dev/null || command -v sift-cli &>/dev/null; then
    SIFT_DETECTED=1
fi
if [ "$SIFT_DETECTED" = 1 ]; then
    ok "SIFT Workstation detected — most steps below should say 'already present'; only genuine gaps get installed"
else
    ok "No SIFT Workstation detected — installing the full forensic toolchain from a plain host"
fi

# ── 1b. System packages (apt) ─────────────────────────────────────────────────

step "Installing system packages (Python base + forensic tools)"

APT_PACKAGES=(
    curl               # chainsaw/EZ Tools/Hayabusa/.NET downloads all shell
                       # out to it — same "assumed present" gap as git above,
                       # found the same way.
    ca-certificates    # curl needs these to verify the HTTPS downloads above
    git                # RegRipper (step below) fetches by commit SHA — not
                       # safe to assume present. True on a SIFT workstation
                       # or a full Ubuntu Desktop, not on a minimal base
                       # image.
    python3-venv       # ensurepip — required by `python3 -m venv`
    python3-pip        # pip bootstrap for the venv
    fonts-dejavu-core  # the PDF report's typeface. fpdf2's built-in fonts are
                       # Latin-1 only, so without a Unicode face an em dash --
                       # which Atlas prose uses throughout -- fails the export
                       # before any evidence text is reached. -core carries the
                       # regular and bold faces; -extra below adds the obliques.
    fonts-dejavu-extra # true italics. Optional: without it emphasis renders
                       # upright rather than failing (see core/report_pdf.py).
    sqlite3            # ad-hoc queries on browser, sync-client and app databases
    binutils           # strings — the strings.* tools; absent on minimal cloud images
    file               # file type by content (strings.file_type, crypto)
    xxd                # hex dumps (strings.xxd)
    bsdextrautils      # hexdump (strings.hexdump)
    pff-tools          # pffexport — PST/OST email extraction
    pst-utils          # readpst — PST→mbox conversion
    binwalk            # firmware / embedded carving
    tcpxtract          # network stream carving
    sleuthkit          # TSK tools
    libparse-win32registry-perl  # Parse::Win32Registry — RegRipper (rip.pl) hive parsing
    unzip              # EZ Tools archives (step 1cy) ship as .zip
    foremost           # file carving by header/footer signature
    scalpel            # file carving (faster than foremost on large images)
    steghide           # steganography: steghide embeddings in JPEG/BMP/WAV/AU
    outguess           # steganography: outguess embeddings in JPEG/PNM
    testdisk           # provides both testdisk and photorec
    clamav             # clamscan — AV signature scan
    libimage-exiftool-perl  # exiftool — artifact/media metadata
    ssdeep             # fuzzy hashing
    hashdeep           # hashdeep/md5deep-family hashing
    qemu-utils         # qemu-img — VMDK/qcow2 handling
    # ewf-tools/libbde-utils/libvshadow-utils/xmount deliberately NOT here —
    # they Conflict: with GIFT PPA's plaso-tools (a hard Depends: of
    # python3-plaso), so which package generation is correct isn't knowable
    # until after the Plaso step decides whether GIFT was used. See step
    # 1cw2 ("Installing forensic image-mount tools") below.
    parted             # partprobe — re-read partition table after a loop/image mount
    tcpdump            # tools/network.py's pcap-read/http-extract tools shell out to it directly
    ngrep              # net.ngrep_search — pattern search across packet payloads
    ntfs-3g            # tools/ewf.py's mounts rely on the OS resolving NTFS via ntfs-3g/fuseblk
    p7zip-full         # 7z — tools/archives.py's archive_extract_7z
    unrar              # tools/archives.py's archive_extract_rar (lives in Ubuntu's multiverse — see below)
)

MISSING_PKGS=()
for pkg in "${APT_PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        MISSING_PKGS+=("$pkg")
    fi
done
if [ "${#MISSING_PKGS[@]}" -gt 0 ]; then
    # pst-utils, pff-tools, and tcpxtract live in the 'universe' component.
    # SIFT normally enables it, but a bare Ubuntu base may not — make it explicit
    # so a fresh image doesn't fail with "unable to locate package". (Debian has
    # no 'universe' concept — these packages live in 'main'/'contrib' there.)
    if [ "$OS_ID" = "ubuntu" ] && ! grep -rq "^deb .* universe" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
        if command -v add-apt-repository &>/dev/null; then
            sudo add-apt-repository -y universe || warn "Could not enable 'universe' repo automatically"
        else
            warn "'universe' repo not enabled and add-apt-repository missing — some packages may not install"
        fi
    fi
    # unrar lives in 'multiverse' (non-free), not 'universe'. Same fresh-image
    # gap as above — enable it explicitly rather than let the package fail
    # silently into the "retrying individually" fallback below. Debian's
    # equivalent is contrib/non-free, which this installer doesn't attempt to
    # enable automatically (unrar is fail-open there — see MISSING_PKGS retry).
    if [ "$OS_ID" = "ubuntu" ] && ! grep -rq "^deb .* multiverse" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
        if command -v add-apt-repository &>/dev/null; then
            sudo add-apt-repository -y multiverse || warn "Could not enable 'multiverse' repo automatically"
        else
            warn "'multiverse' repo not enabled and add-apt-repository missing — unrar may not install"
        fi
    fi
    # libbde/libewf/libvshadow (bare, unversioned names) are not valid
    # package names in Ubuntu's own archive — jammy and noble both only ship
    # the versioned libewf2/libbde1(t64)/libvshadow1 there (see
    # packages.ubuntu.com). They ARE valid, current packages once the
    # GIFT PPA (added below for Plaso) is enabled — GIFT's own
    # libewf/libbde/libvshadow are what python3-plaso/python3-dfvfs hard-
    # depend on (apt-cache depends python3-plaso lists them as Depends:,
    # not Suggests:). So a bare-named package on disk is either
    # leftover from an older Atlas install (uninstall.sh deliberately never
    # removes apt packages by default) — safe to drop — or GIFT's package
    # backing a Plaso install that's already working — must NOT be dropped,
    # or python3-plaso breaks. Either way it Conflicts with libbde-utils/
    # ewf-tools/xmount/libvshadow-utils's real dependencies (apt reports
    # "libewf : Conflicts: libewf2 but 20140814-1build3 is to be installed"),
    # blocking the whole batch, so it still needs handling — just not by
    # unconditional removal.
    if dpkg -s python3-plaso &>/dev/null || dpkg -s python3-dfvfs &>/dev/null; then
        ok "GIFT PPA's libbde/libewf/libvshadow are in active use by an installed Plaso — leaving them; ewf-tools/libbde-utils/libvshadow-utils/xmount below will be skipped in favor of GIFT's own libewf-tools/libbde-tools/libvshadow-tools (see step 1cw2)"
    else
        for legacy_pkg in libbde libewf libvshadow; do
            if dpkg -s "$legacy_pkg" &>/dev/null; then
                warn "Removing legacy package '$legacy_pkg' — conflicts with current forensic-tool packages, safe to drop (no Plaso installation currently depends on it)"
                sudo apt-get remove -y "$legacy_pkg" || true
            fi
        done
    fi

    sudo apt-get update -qq
    INSTALLED_PKGS=()
    if sudo apt-get install -y "${MISSING_PKGS[@]}"; then
        record_pkgs "${MISSING_PKGS[@]}"
        INSTALLED_PKGS=("${MISSING_PKGS[@]}")
    else
        # Fall back to installing what we can individually — one bad package
        # name (e.g. a rename between releases) shouldn't sink the whole batch.
        warn "Batch apt install failed — retrying packages individually"
        for pkg in "${MISSING_PKGS[@]}"; do
            if sudo apt-get install -y "$pkg" 2>/dev/null; then
                record_pkgs "$pkg"
                INSTALLED_PKGS+=("$pkg")
            else
                warn "Could not install '$pkg' — the features it backs will report unavailable"
            fi
        done
    fi

    # Verify the critical binaries actually landed — dpkg state alone can report
    # success while an apt failure (swallowed above) left a tool absent.
    for bin in readpst pffexport; do
        command -v "$bin" &>/dev/null || warn "Expected binary '$bin' not found after install — email extraction (misc.readpst_extract / misc.pff_export) will fail"
    done
    # Report exactly what landed, not the pre-attempt wishlist — a package
    # that failed above (batch or individual retry) must not be claimed here.
    if [ "${#INSTALLED_PKGS[@]}" -gt 0 ]; then
        ok "Installed: ${INSTALLED_PKGS[*]}"
    fi
    if [ "${#INSTALLED_PKGS[@]}" -lt "${#MISSING_PKGS[@]}" ]; then
        warn "$(( ${#MISSING_PKGS[@]} - ${#INSTALLED_PKGS[@]} )) package(s) could not be installed — see the 'Could not install' warnings above"
    fi
else
    ok "All apt forensic packages already present"
fi

# bulk_extractor gets its own tier: it's had availability gaps on some recent
# Ubuntu/Debian releases as the upstream project changed hands, and it isn't
# in Ubuntu 22.04's, Ubuntu 24.04's, or Debian 12's archives today. Unlike TIER3 below,
# it's not a nice-to-have: it's part of the
# playbook's own "foundation batch" (hub/playbook/05_tool_namespaces.md),
# started early on every disk-image case alongside Plaso and Hayabusa — so a
# source build is worth attempting rather than just warning and stopping.
# Upstream's own CI validates this exact recipe on Ubuntu 22.04
# (doc/installation.md in their repo, package list below matches it);
# libewf-dev is added on top of their CI list (which deliberately disables
# E01 to keep their own build matrix simple) since Atlas evidence is
# routinely E01 and ewf-tools is provisioned later (step 1cw2, after Plaso
# decides which libewf generation wins). `make check`
# (upstream's own test suite) is deliberately skipped — this installer wants
# the binary, not a multi-minute validation run of someone else's tests.
if dpkg -s bulk-extractor &>/dev/null || command -v bulk_extractor &>/dev/null; then
    ok "bulk_extractor already present"
elif sudo apt-get install -y bulk-extractor 2>/dev/null; then
    record_pkgs bulk-extractor
    ok "Installed bulk_extractor"
else
    BE_BUILD_DEPS=(autoconf automake build-essential flex libabsl-dev
        libexpat1-dev libgcrypt20-dev libgpg-error-dev libre2-dev libssl-dev
        libtool make pkg-config procps python3 zlib1g-dev libewf-dev)
    BE_DIR="/opt/bulk_extractor"
    BE_LOG="$(mktemp)"
    if sudo apt-get install -y "${BE_BUILD_DEPS[@]}" &>>"$BE_LOG" \
        && sudo rm -rf "$BE_DIR" \
        && sudo git clone --quiet https://github.com/simsong/bulk_extractor.git "$BE_DIR" &>>"$BE_LOG" \
        && ( cd "$BE_DIR" \
             && sudo ./bootstrap.sh &>>"$BE_LOG" \
             && sudo ./configure &>>"$BE_LOG" \
             && sudo make -j"$(nproc)" &>>"$BE_LOG" \
             && sudo make install &>>"$BE_LOG" ) \
        && command -v bulk_extractor &>/dev/null; then
        record_path dir "$BE_DIR"
        ok "Built bulk_extractor from source (no Ubuntu/Debian package today) → $(command -v bulk_extractor)"
    else
        warn "Building bulk_extractor from source failed (log: $BE_LOG) — carving.bulk_extractor_scan will report unavailable. This is a foundation-batch tool (hub/playbook/05_tool_namespaces.md), not just a nice-to-have — worth another look, not just accepting the gap. Manual build: https://github.com/simsong/bulk_extractor/blob/main/doc/installation.md"
        sudo rm -rf "$BE_DIR"
    fi
fi

# Tier-3 best-effort extras: small, low-risk, no special handling needed
# beyond the same missing-package loop. tshark's postinst asks an interactive
# debconf question about non-root packet capture unless preseeded — do that
# regardless of DEBIAN_FRONTEND to be safe.
echo "wireshark-common wireshark-common/install-setuid boolean false" | sudo debconf-set-selections 2>/dev/null || true

TIER3_PACKAGES=(whois upx-ucl tshark)
TIER3_MISSING=()
for pkg in "${TIER3_PACKAGES[@]}"; do
    dpkg -s "$pkg" &>/dev/null || TIER3_MISSING+=("$pkg")
done
if [ "${#TIER3_MISSING[@]}" -gt 0 ]; then
    for pkg in "${TIER3_MISSING[@]}"; do
        if sudo apt-get install -y "$pkg" 2>/dev/null; then
            record_pkgs "$pkg"
        else
            warn "Optional package '$pkg' not available — the matching tool degrades gracefully"
        fi
    done
    ok "Attempted optional extras: ${TIER3_MISSING[*]}"
else
    ok "Optional extras (whois/upx/tshark) already present"
fi

# radare2: Ubuntu 22.04's apt package has no candidate at all, so the fallback below is a source build via upstream's
# official one-script installer (sys/install.sh). Ubuntu 24.04 DOES have an
# apt candidate — try that
# first now, it's simpler to manage and to uninstall than a source build.
# Unlike bulk_extractor's Makefile build, the source-build fallback must NOT
# run under sudo end-to-end — the script deliberately compiles as the
# invoking user and escalates internally only for the /usr/local install
# step (running the whole thing as root breaks it: it fails with permission
# errors from an unrelated ownership mismatch the script doesn't expect). The
# installed binaries are symlinks back into RADARE2_DIR, not copies —
# deleting that directory after a "successful" install silently breaks r2.
# record_path keeps
# it in the manifest so uninstall.sh knows this, and `cd RADARE2_DIR &&
# make purge` is the documented way to remove it cleanly.
if command -v r2 &>/dev/null || command -v radare2 &>/dev/null; then
    ok "radare2 already present"
elif sudo apt-get install -y radare2 &>/dev/null; then
    record_pkgs radare2
    ok "Installed radare2 (apt)"
else
    RADARE2_DIR="/opt/radare2"
    RADARE2_LOG="$(mktemp)"
    if sudo apt-get install -y build-essential pkg-config git &>>"$RADARE2_LOG" \
        && sudo rm -rf "$RADARE2_DIR" \
        && sudo mkdir -p "$RADARE2_DIR" \
        && sudo chown "$(id -un):$(id -gn)" "$RADARE2_DIR" \
        && git clone --quiet https://github.com/radareorg/radare2 "$RADARE2_DIR" &>>"$RADARE2_LOG" \
        && ( cd "$RADARE2_DIR" && ./sys/install.sh &>>"$RADARE2_LOG" ) \
        && command -v r2 &>/dev/null; then
        record_path radare2 "$RADARE2_DIR"
        ok "Built radare2 from source (no apt candidate today) → $(command -v r2)"
    else
        warn "Building radare2 from source failed (log: $RADARE2_LOG) — the matching bintriage tool degrades gracefully. Manual install: git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh"
        sudo rm -rf "$RADARE2_DIR"
    fi
fi

# Optional, heavier network-monitoring tools — asked, not attempted by
# default, since they're their own repos/large and not core to disk/memory
# forensics.
if [ "$WITH_NETWORK_TOOLS" != 1 ]; then
    ask_yn "Install optional network-monitoring tools (zeek, suricata)?" n
    [ "$REPLY_YN" = 1 ] && WITH_NETWORK_TOOLS=1
fi
if [ "$WITH_NETWORK_TOOLS" = 1 ]; then
    step "Installing optional network-monitoring tools"
    # suricata is already in Ubuntu's universe / Debian's own repos — the
    # loop below handles it like any other apt package. zeek has no
    # candidate in either release's own repos at all, but zeek's own project publishes an official openSUSE
    # Build Service repo covering both hardened targets
    #. Only reached once the user has already
    # opted into --with-network-tools, so adding this one extra
    # third-party repo is exactly the tradeoff they asked for, not a
    # surprise. zeek-lts (not the rolling `zeek` package) to match this
    # installer's own LTS-only hardened-target posture.
    if ! dpkg -s zeek-lts &>/dev/null && ! command -v zeek &>/dev/null; then
        ZEEK_OBS_DIST=""
        case "$OS_ID" in
            ubuntu) ZEEK_OBS_DIST="xUbuntu_${OS_VERSION}" ;;
            debian) ZEEK_OBS_DIST="Debian_${OS_VERSION}" ;;
        esac
        if [ -n "$ZEEK_OBS_DIST" ]; then
            ZEEK_REPO_URL="https://download.opensuse.org/repositories/security:/zeek/${ZEEK_OBS_DIST}/"
            sudo apt-get install -y gnupg &>/dev/null || true
            if add_apt_repo_with_key "${ZEEK_REPO_URL}Release.key" \
                    /etc/apt/sources.list.d/security-zeek.list \
                    /etc/apt/trusted.gpg.d/security-zeek.gpg \
                    "deb $ZEEK_REPO_URL /"; then
                sudo apt-get update -qq
                MANIFEST_FLAG_ZEEK_REPO=1
            else
                warn "Could not add zeek's package repo ($ZEEK_REPO_URL) — offline, or the key/list write failed. zeek install below will fail; see https://zeek.org/get-zeek/ to add it manually."
            fi
        fi
    fi
    # zeek-lts pulls in zeekctl-lts → postfix (mail alerting) transitively.
    # postfix's own postinst asks an interactive debconf question about
    # mail-server configuration type that DEBIAN_FRONTEND=noninteractive
    # alone does not silence (confirmed live — it hangs apt indefinitely
    # without this) — same class of preseed already needed for tshark
    # above, just a different package/question.
    echo "postfix postfix/main_mailer_type select No configuration" | sudo debconf-set-selections 2>/dev/null || true
    for pkg in zeek-lts suricata; do
        if dpkg -s "$pkg" &>/dev/null || command -v "${pkg%-lts}" &>/dev/null; then
            ok "$pkg already present"
        elif sudo apt-get install -y "$pkg" 2>/dev/null; then
            record_pkgs "$pkg"
            ok "Installed $pkg"
        else
            warn "'$pkg' could not be installed — see https://zeek.org/get-zeek/ or https://suricata.io/download/ to add it manually. network.* tools using it stay unavailable until then."
        fi
    done
fi

# ── 1bb. Optional SMB network share (evidence intake without SSH) ────────────
# Only installs the samba package and records intent here — the actual share
# config (`bin/atlas share enable`) is written later, after step 2 installs
# the sudoers grant that `atlas-smb-share enable` needs to run at all.
if [ "$WITH_NETWORK_SHARE" != 1 ] && [ "$RUNNING_AS_ROOT" != 1 ]; then
    ask_yn "Set up an SMB network share so evidence can be copied in from Windows without SSH? (installs samba, opens ports 139/445 on whatever interface your firewall allows)" n
    [ "$REPLY_YN" = 1 ] && WITH_NETWORK_SHARE=1
fi
if [ "$WITH_NETWORK_SHARE" = 1 ] && [ "$RUNNING_AS_ROOT" = 1 ]; then
    warn "Running as root — skipping the network share (it authenticates via this user's own sudoers grant, which install.sh skips for root; see share/atlas-sudoers.in). Run install.sh as a normal user to enable it."
    WITH_NETWORK_SHARE=0
fi
if [ "$WITH_NETWORK_SHARE" = 1 ]; then
    step "Installing samba for the network share"
    if dpkg -s samba &>/dev/null; then
        ok "samba already installed"
    elif sudo apt-get install -y samba 2>/dev/null; then
        record_pkgs samba
        ok "Installed samba"
    else
        warn "Could not install samba — the network share will be unavailable. Try: sudo apt-get install -y samba, then: bin/atlas-sudoers && bin/atlas share enable"
        WITH_NETWORK_SHARE=0
    fi
fi

# ── 1c. Chainsaw (Sigma rule engine for EVTX) ────────────────────────────────

step "Installing chainsaw (optional: Sigma rule engine)"

CHAINSAW_BIN="/usr/local/bin/chainsaw"
# CHAINSAW_VERSION comes from install-versions.env (sourced above)

if [ -x "$CHAINSAW_BIN" ]; then
    ok "chainsaw already installed at $CHAINSAW_BIN"
else
    CHAINSAW_URL="https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VERSION}/chainsaw_x86_64-unknown-linux-gnu.tar.gz"
    CHAINSAW_TMP=$(mktemp -d)
    if curl -fsSL "$CHAINSAW_URL" -o "$CHAINSAW_TMP/chainsaw.tgz" 2>/dev/null; then
        # Guard extraction: a corrupt download must degrade to the optional-skip
        # path, not abort the whole install under `set -e`.
        # Release ships as chainsaw/chainsaw + sigma rules
        if ! tar -xzf "$CHAINSAW_TMP/chainsaw.tgz" -C "$CHAINSAW_TMP" 2>/dev/null; then
            warn "chainsaw archive corrupt — skipping (Atlas works without it)"
        elif [ -f "$CHAINSAW_TMP/chainsaw/chainsaw" ]; then
            sudo install -m 0755 "$CHAINSAW_TMP/chainsaw/chainsaw" "$CHAINSAW_BIN"
            record_path file "$CHAINSAW_BIN"
            # mkdir must NOT sit inside the sigma guard: an archive with
            # mappings/ but no sigma/ would leave the parent absent and abort
            # the whole install at the second cp under `set -e`.
            sudo mkdir -p /usr/local/share/chainsaw
            record_path dir /usr/local/share/chainsaw
            if [ -d "$CHAINSAW_TMP/chainsaw/sigma" ]; then
                sudo cp -r "$CHAINSAW_TMP/chainsaw/sigma" /usr/local/share/chainsaw/sigma
            fi
            if [ -d "$CHAINSAW_TMP/chainsaw/mappings" ]; then
                sudo cp -r "$CHAINSAW_TMP/chainsaw/mappings" /usr/local/share/chainsaw/mappings
            fi
            # The release carries no Sigma rule set — without one, hunt has
            # nothing to match and misc.chainsaw_hunt refuses to run.
            if [ ! -d /usr/local/share/chainsaw/sigma ]; then
                if git clone --depth 1 --quiet https://github.com/SigmaHQ/sigma "$CHAINSAW_TMP/sigma" 2>/dev/null \
                        && [ -d "$CHAINSAW_TMP/sigma/rules" ]; then
                    sudo cp -r "$CHAINSAW_TMP/sigma/rules" /usr/local/share/chainsaw/sigma
                    ok "Installed the Sigma rule set → /usr/local/share/chainsaw/sigma"
                else
                    warn "Could not fetch the Sigma rule set (offline?) — misc.chainsaw_hunt needs sigma_dir until it is installed"
                fi
            fi
            ok "Installed chainsaw v${CHAINSAW_VERSION} → $CHAINSAW_BIN"
        else
            warn "chainsaw archive layout unexpected; skipping"
        fi
    else
        warn "Could not download chainsaw (offline?). Skip — Atlas works without it."
    fi
    rm -rf "$CHAINSAW_TMP"
fi

# chainsaw's $MFT rules (kind: mft), which misc.mft_rule_hunt reads, are not
# in the Linux release archive; the source archive of the same tag carries
# them. Only that folder is unpacked (the archive also holds sample event
# logs of attacks), and only what this step adds is recorded for
# uninstall. Checked on every run, so a host that got the binary earlier
# gets the rules too.
if [ -x "$CHAINSAW_BIN" ] && [ ! -d /usr/local/share/chainsaw/rules/mft ]; then
    CHAINSAW_RULES_TMP=$(mktemp -d)
    CHAINSAW_SRC_URL="https://github.com/WithSecureLabs/chainsaw/archive/refs/tags/v${CHAINSAW_VERSION}.tar.gz"
    if curl -fsSL "$CHAINSAW_SRC_URL" -o "$CHAINSAW_RULES_TMP/src.tgz" 2>/dev/null \
            && tar -xzf "$CHAINSAW_RULES_TMP/src.tgz" -C "$CHAINSAW_RULES_TMP" \
                   --wildcards "*/rules/mft/*" 2>/dev/null \
            && [ -d "$CHAINSAW_RULES_TMP/chainsaw-${CHAINSAW_VERSION}/rules/mft" ]; then
        if [ ! -d /usr/local/share/chainsaw/rules ]; then
            sudo mkdir -p /usr/local/share/chainsaw/rules
            record_path dir /usr/local/share/chainsaw/rules
        fi
        sudo cp -r "$CHAINSAW_RULES_TMP/chainsaw-${CHAINSAW_VERSION}/rules/mft" /usr/local/share/chainsaw/rules/
        record_path dir /usr/local/share/chainsaw/rules/mft
        ok "Installed chainsaw's \$MFT rules → /usr/local/share/chainsaw/rules/mft"
    else
        warn "Could not fetch chainsaw's rule set (offline?) — misc.mft_rule_hunt needs rules_dir until it is installed"
    fi
    rm -rf "$CHAINSAW_RULES_TMP"
fi

# ── 1cv. Volatility 3 (memory forensics) ─────────────────────────────────────

step "Installing Volatility 3 (memory forensics)"

# The pip package (installed into .venv below at step 3) provides a `vol`
# console-script; core/paths.py:vol3_bin() now checks PATH before falling
# back to SIFT's own convention of /usr/local/bin/vol, but we still symlink
# it there too so anything (docs, muscle memory, a shell alias) expecting
# that exact path keeps working. The actual `pip install` happens with the
# rest of requirements.txt in step 3 — this step just does the symlink once
# the venv exists, and is safe to re-run.
# (See step 3 for the symlink itself — ordering requires the venv first.)
ok "Volatility 3 will install via requirements.txt (pip) in step 3"

# ── 1cw. Plaso (super-timelines) ─────────────────────────────────────────────

step "Installing Plaso (log2timeline/psort — super-timelines)"

if command -v log2timeline.py &>/dev/null; then
    ok "Plaso already installed ($(command -v log2timeline.py))"
elif [ "$OS_ID" = "ubuntu" ]; then
    # GIFT PPA is what SIFT itself uses — prebuilt, most reliable on Ubuntu.
    PLASO_OK=0
    if command -v add-apt-repository &>/dev/null; then
        if sudo add-apt-repository -y ppa:gift/stable 2>/dev/null; then
            MANIFEST_FLAG_GIFT_PPA=1
            sudo apt-get update -qq
            if sudo apt-get install -y plaso-tools 2>/dev/null; then
                record_pkgs plaso-tools
                PLASO_OK=1
                ok "Installed Plaso via ppa:gift/stable"
            fi
        fi
    fi
    if [ "$PLASO_OK" != 1 ]; then
        warn "GIFT PPA install failed (offline, or repo unavailable for this release) — falling back to pip install plaso. This path is less tested than the PPA."
        if [ -x "$VENV_DIR/bin/pip" ]; then
            "$VENV_DIR/bin/pip" install --quiet plaso 2>/dev/null && ok "Installed Plaso via pip" \
                || warn "pip install plaso failed — plaso.* tools will report unavailable"
        else
            ok "Will attempt Plaso via pip in step 3 once the venv exists"
        fi
    fi
else
    # Debian: no GIFT PPA. pip is the primary (and only) path here.
    warn "Installing Plaso via pip (no GIFT PPA on Debian) — this is less tested than the Ubuntu path; if it fails, plaso.* tools report unavailable and the rest of Atlas is unaffected."
    if [ -x "$VENV_DIR/bin/pip" ]; then
        "$VENV_DIR/bin/pip" install --quiet plaso 2>/dev/null && ok "Installed Plaso via pip" \
            || warn "pip install plaso failed — plaso.* tools will report unavailable"
    else
        ok "Will attempt Plaso via pip in step 3 once the venv exists"
    fi
fi

# ── 1cw2. Forensic image-mount tools (ewfmount/bdemount/vshadowmount/xmount) ─
# Deliberately deferred from APT_PACKAGES to here, after Plaso: Ubuntu
# archive's ewf-tools/libbde-utils/libvshadow-utils depend on
# libewf2/libbde1t64/libvshadow1t64, but GIFT PPA's plaso-tools hard-depends
# (Depends:, not Suggests:, per apt-cache depends) on GIFT's
# own libewf/libbde/libvshadow — same libraries, incompatible packages, and
# they Conflict:. Installing plaso-tools after ewf-tools silently
# force-removes ewf-tools/libbde-utils/libvshadow-utils/xmount with no
# warning at all, which leaves ewfmount missing after an install that
# reported success. GIFT ships its own
# libewf-tools/libbde-tools/libvshadow-tools under different names providing
# the identical ewfmount/bdemount/vshadowmount binaries, built against GIFT's
# libewf/libbde/libvshadow — dependency-compatible with GIFT-Plaso (they
# install cleanly and log2timeline.py still runs afterward). xmount has
# no GIFT-built equivalent anywhere in the PPA — it only exists linked
# against Ubuntu's own libewf2, so it Conflicts: with GIFT's libewf no matter
# what; that's a real, unavoidable gap when Plaso came from GIFT, not a bug
# to keep chasing — qemu-img (already installed above) and ewfmount cover
# most of the same format-conversion ground.
step "Installing forensic image-mount tools (ewfmount/bdemount/vshadowmount/xmount)"
if dpkg -s libewf &>/dev/null; then
    ok "GIFT PPA's libewf/libbde/libvshadow are active (Plaso installed from GIFT) — using GIFT's matching -tools packages"
    if apt_install_new libewf-tools libbde-tools libvshadow-tools; then
        ok "ewfmount/bdemount/vshadowmount available (GIFT PPA build)"
    else
        warn "Could not install libewf-tools/libbde-tools/libvshadow-tools — ewfmount/bdemount/vshadowmount will report unavailable"
    fi
    if apt_install_new xmount 2>/dev/null; then
        ok "xmount available"
    else
        warn "xmount is not installable alongside GIFT PPA's Plaso (both ship incompatible libewf builds, and GIFT has no xmount-compatible equivalent). qemu-img and ewfmount (already installed) cover the same ground for Atlas's own tools. To build real xmount by hand instead, see docs/xmount-manual-install.md."
    fi
else
    if apt_install_new ewf-tools libbde-utils libvshadow-utils xmount; then
        ok "ewfmount/bdemount/vshadowmount/xmount available"
    else
        warn "Could not install ewf-tools/libbde-utils/libvshadow-utils/xmount — image-mounting tools will report unavailable"
    fi
fi

# ── 1cx. RegRipper (registry hive parsing via rip.pl) ────────────────────────

step "Installing ESE database and legacy event-log exporters (esedbexport, evtexport)"
# libyal's exporters: SRUM, WebCache and Windows.edb (ese.*) and pre-Vista
# .evt logs (evt.*). Ubuntu ships them as -utils; the GIFT PPA, when Plaso
# came from it, ships newer builds as -tools that replace the Ubuntu ones.
if dpkg -s libewf &>/dev/null; then
    LIBYAL_PKGS=(libesedb-tools libevt-tools)
else
    LIBYAL_PKGS=(libesedb-utils libevt-utils)
fi
if command -v esedbexport &>/dev/null && command -v evtexport &>/dev/null; then
    ok "esedbexport and evtexport already installed"
elif apt_install_new "${LIBYAL_PKGS[@]}"; then
    ok "esedbexport and evtexport available (${LIBYAL_PKGS[*]})"
else
    warn "Could not install ${LIBYAL_PKGS[*]} — ese.esedb_export and evt.evt_export will report their program as missing"
fi

step "Installing RegRipper (registry hive parsing)"

# misc.regripper_hive shells out to /usr/local/bin/rip.pl, a thin wrapper around
# a keydet89/RegRipper4.0 checkout in /opt. Provision both so a fresh onboard
# gets a working rip.pl; Parse::Win32Registry comes from the
# libparse-win32registry-perl apt package installed above. Degrade to a warning
# rather than aborting under `set -e` — Atlas falls back to ez.recmd_hive when
# RegRipper is unavailable. (sudo git here is correct: /opt/regripper is a
# system-wide, root-owned tool checkout, not a user's Atlas clone.)
REGRIPPER_DIR="/opt/regripper"
RIP_WRAPPER="/usr/local/bin/rip.pl"

if [ -f "$REGRIPPER_DIR/rip.pl" ] && [ -x "$RIP_WRAPPER" ]; then
    ok "RegRipper already installed ($REGRIPPER_DIR)"
else
    if [ ! -f "$REGRIPPER_DIR/rip.pl" ]; then
        # RegRipper4.0 ships no tags/releases — pin to an exact commit SHA
        # (REGRIPPER_REF, install-versions.env) instead of cloning whatever
        # `main` happens to be at install time. A plain `git clone` can't
        # target an arbitrary SHA; this is the shallow-fetch-by-SHA
        # equivalent (GitHub supports fetching any reachable commit this way).
        if sudo mkdir -p "$REGRIPPER_DIR" \
           && sudo git -C "$REGRIPPER_DIR" init -q \
           && sudo git -C "$REGRIPPER_DIR" remote add origin \
                https://github.com/keydet89/RegRipper4.0.git \
           && sudo git -C "$REGRIPPER_DIR" fetch --depth 1 origin "$REGRIPPER_REF" 2>/dev/null \
           && sudo git -C "$REGRIPPER_DIR" checkout -q FETCH_HEAD; then
            record_path dir "$REGRIPPER_DIR"
        else
            warn "Could not fetch RegRipper @ ${REGRIPPER_REF:0:12} (offline, or the pinned commit is gone — see install-versions.env). Skip — Atlas falls back to ez.recmd_hive."
            sudo rm -rf "$REGRIPPER_DIR"
        fi
    fi
    if [ -f "$REGRIPPER_DIR/rip.pl" ]; then
        # Wrapper runs rip.pl from its own dir so it finds plugins/ and -I libs.
        sudo tee "$RIP_WRAPPER" >/dev/null <<EOF
#!/bin/bash
cd $REGRIPPER_DIR && exec perl -I$REGRIPPER_DIR rip.pl "\$@"
EOF
        sudo chmod +x "$RIP_WRAPPER"
        record_path file "$RIP_WRAPPER"
        ok "Installed RegRipper wrapper → $RIP_WRAPPER"
    fi
fi

# Verify rip.pl can actually load its plugins (catches a missing
# Parse::Win32Registry or an empty plugins/ dir before the first case run).
if [ -x "$RIP_WRAPPER" ] && "$RIP_WRAPPER" -l >/dev/null 2>&1; then
    ok "rip.pl operational ($("$RIP_WRAPPER" -l 2>/dev/null | grep -c '^[0-9]') plugins)"
else
    warn "rip.pl not operational — check 'perl -MParse::Win32Registry -e1' and $REGRIPPER_DIR/plugins (misc.regripper_hive will be unavailable; ez.recmd_hive still works)"
fi

# ── 1cy. EZ Tools (Eric Zimmerman's Windows artifact parsers) ────────────────

step "Installing EZ Tools (Windows artifact parsers)"

# tools/eztools.py shells out to `dotnet <EZ_DIR>/<Tool>.dll`. SIFT Workstation
# pre-seeds /opt/zimmermantools, but a bare host (e.g. a stock Ubuntu cloud VM)
# has nothing there, leaving the entire ez.* family unavailable on Windows
# cases. Provision the tools ourselves, with the same posture as chainsaw and
# RegRipper above: optional, download-failure tolerant, degrading to a warning
# instead of aborting under `set -e`.
EZ_DIR="${ATLAS_EZ_TOOLS:-/opt/zimmermantools}"
EZ_BASE_URL="https://download.mikestammer.com/net9"   # net6 zips are gone (404)

# Every tool tools/eztools.py can invoke. EvtxeCmd, RECmd and SQLECmd ship their
# own folder INSIDE the zip, so ALL archives extract into $EZ_DIR itself —
# pre-creating the subdir would nest it twice (…/EvtxeCmd/EvtxeCmd/EvtxECmd.dll).
EZ_TOOLS=(
    MFTECmd EvtxECmd RECmd SQLECmd AmcacheParser AppCompatCacheParser PECmd
    JLECmd LECmd SBECmd RBCmd WxTCmd RecentFileCacheParser bstrings rla SrumECmd
    SumECmd
)

# Sentinel: the file eztools.py actually runs, relative to $EZ_DIR. (The EvtxECmd
# archive's directory is spelled 'EvtxeCmd' — lowercase 'e' — while the dll is
# 'EvtxECmd.dll'; eztools.py expects exactly that.)
ez_dll() {
    case "$1" in
        EvtxECmd) echo "EvtxeCmd/EvtxECmd.dll" ;;
        RECmd)    echo "RECmd/RECmd.dll" ;;
        SQLECmd)  echo "SQLECmd/SQLECmd.dll" ;;
        *)        echo "$1.dll" ;;
    esac
}

# /opt needs root, but honour a user-writable ATLAS_EZ_TOOLS without sudo.
EZ_SUDO="sudo"
if { [ -d "$EZ_DIR" ] && [ -w "$EZ_DIR" ]; } \
   || { [ ! -e "$EZ_DIR" ] && [ -w "$(dirname "$EZ_DIR")" ]; }; then
    EZ_SUDO=""
fi
ez_run() { if [ -n "$EZ_SUDO" ]; then sudo "$@"; else "$@"; fi; }

EZ_MISSING=()
for ez_tool in "${EZ_TOOLS[@]}"; do
    [ -f "$EZ_DIR/$(ez_dll "$ez_tool")" ] || EZ_MISSING+=("$ez_tool")
done

if [ "${#EZ_MISSING[@]}" -eq 0 ]; then
    ok "EZ Tools already installed (${#EZ_TOOLS[@]} tools in $EZ_DIR)"
elif ! command -v unzip &>/dev/null; then
    warn "unzip not found — cannot install ${#EZ_MISSING[@]} missing EZ Tools. Install unzip and re-run; the ez.* tools stay unavailable until then."
else
    ez_run mkdir -p "$EZ_DIR"
    record_path dir "$EZ_DIR"
    EZ_TMP=$(mktemp -d)
    EZ_FAILED=()
    for ez_tool in "${EZ_MISSING[@]}"; do
        if ! curl -fsSL "$EZ_BASE_URL/$ez_tool.zip" -o "$EZ_TMP/$ez_tool.zip" 2>/dev/null; then
            EZ_FAILED+=("$ez_tool")
        elif ! ez_run unzip -q -o "$EZ_TMP/$ez_tool.zip" -d "$EZ_DIR" 2>/dev/null; then
            EZ_FAILED+=("$ez_tool")   # corrupt archive — skip, don't abort
        elif [ ! -f "$EZ_DIR/$(ez_dll "$ez_tool")" ]; then
            EZ_FAILED+=("$ez_tool")   # layout changed upstream
        fi
        rm -f "$EZ_TMP/$ez_tool.zip"
    done
    rm -rf "$EZ_TMP"
    if [ "${#EZ_FAILED[@]}" -eq 0 ]; then
        ok "Installed ${#EZ_MISSING[@]} EZ Tools → $EZ_DIR"
    else
        warn "EZ Tools partially installed (offline?) — unavailable: ${EZ_FAILED[*]}. Atlas works without them; the matching ez.* tools will report unavailable."
    fi
fi

# Normalize permissions unconditionally — this is also the fix path for machines
# that already have the tools. The archives carry FAT attributes, not Unix ones,
# so unzip derives modes from the extracting shell's umask; under a umask with
# the o+x bit set (e.g. 0003) subdirs land at 774 (drwxrwxr--). 'Other' then
# lacks the traverse bit and every NON-owner analyst on a shared VM hits
# PermissionError on e.g. EvtxeCmd/EvtxECmd.dll. 'a+rX' adds read everywhere
# plus execute for directories only (never marks a dll executable).
if [ -d "$EZ_DIR" ]; then
    if ez_run chmod -R a+rX "$EZ_DIR" 2>/dev/null; then
        ok "EZ Tools readable and traversable by all users ($EZ_DIR)"
    else
        warn "Could not normalize permissions on $EZ_DIR — non-owner analysts may hit PermissionError on the ez.* tools; fix with: sudo chmod -R a+rX $EZ_DIR"
    fi
fi

# Prove one tool actually starts, rather than trusting that files exist.
if [ "$DOTNET9_OK" = 1 ] && [ -f "$EZ_DIR/$(ez_dll EvtxECmd)" ]; then
    if dotnet "$EZ_DIR/$(ez_dll EvtxECmd)" --help >/dev/null 2>&1; then
        ok "EZ Tools operational (EvtxECmd runs under .NET $DOTNET_RUNTIME)"
    else
        warn "EvtxECmd would not start — check 'dotnet $EZ_DIR/$(ez_dll EvtxECmd) --help'; the ez.* tools will fail on Windows cases"
    fi
elif [ -f "$EZ_DIR/$(ez_dll EvtxECmd)" ]; then
    warn "EZ Tools installed but no .NET 9 runtime to run them — install dotnet-runtime-9.0 (see prerequisites above)"
fi

# ── 1cz. odl.py (OneDrive sync logs) ─────────────────────────────────────────

step "Installing odl.py (OneDrive sync logs, optional)"
# misc.onedrive_odl runs odl.py (github.com/ydkhatri/OneDrive, MIT) with the
# repo's own interpreter, as a subprocess; its Python dependencies
# (construct, pycryptodome) come with requirements.txt. No releases exist,
# so the pin is an exact commit (ODL_REF, install-versions.env), checked
# with git rev-parse after checkout. Optional: without it the tool says so.
ODL_DIR="/opt/onedrive-odl"
if [ -f "$ODL_DIR/odl.py" ] && [ "$(cat "$ODL_DIR/.atlas-ref" 2>/dev/null)" = "$ODL_REF" ]; then
    ok "odl.py already installed at $ODL_DIR (${ODL_REF:0:12})"
else
    ODL_TMP=$(mktemp -d)
    if git clone --quiet https://github.com/ydkhatri/OneDrive "$ODL_TMP/odl" &>/dev/null \
        && git -C "$ODL_TMP/odl" checkout --quiet "$ODL_REF" &>/dev/null \
        && [ "$(git -C "$ODL_TMP/odl" rev-parse HEAD)" = "$ODL_REF" ] \
        && [ -f "$ODL_TMP/odl/odl.py" ]; then
        sudo mkdir -p "$ODL_DIR"
        sudo install -m 0644 "$ODL_TMP/odl/odl.py" "$ODL_TMP/odl/LICENSE" "$ODL_DIR/"
        echo "$ODL_REF" | sudo tee "$ODL_DIR/.atlas-ref" >/dev/null
        record_path dir "$ODL_DIR"
        ok "Installed odl.py @ ${ODL_REF:0:12} → $ODL_DIR"
    else
        warn "Could not fetch odl.py @ ${ODL_REF:0:12} (offline, or the pinned commit is gone — see install-versions.env). misc.onedrive_odl reports it missing."
    fi
    rm -rf "$ODL_TMP"
fi


# ── 1cc. Trace dashboard ─────────────────────────────────────────────────────

step "Verifying trace dashboard"

DASHBOARD_HTML="$ATLAS_DIR/dashboard/trace_viewer.html"
DASHBOARD_BIN_SRC="$ATLAS_DIR/bin/atlas-dashboard"
DASHBOARD_BIN_DEST="/usr/local/bin/atlas-dashboard"

if [ -f "$DASHBOARD_HTML" ]; then
    ok "Trace dashboard HTML at $DASHBOARD_HTML"
else
    warn "Trace dashboard HTML not found — dashboard will not work"
fi

if [ -f "$DASHBOARD_BIN_SRC" ]; then
    # Symlink (not copy) so the launcher resolves the repo via its own path
    # and picks up updates without reinstalling.
    if [ "$(readlink -f "$DASHBOARD_BIN_DEST" 2>/dev/null)" = "$DASHBOARD_BIN_SRC" ]; then
        ok "atlas-dashboard already installed at $DASHBOARD_BIN_DEST"
    else
        if sudo ln -sfn "$DASHBOARD_BIN_SRC" "$DASHBOARD_BIN_DEST" 2>/dev/null; then
            record_path symlink "$DASHBOARD_BIN_DEST"
            ok "Installed atlas-dashboard → $DASHBOARD_BIN_DEST"
        else
            warn "Could not install $DASHBOARD_BIN_DEST (sudo needed); use $DASHBOARD_BIN_SRC directly"
        fi
    fi
    echo "    Production:       atlas-dashboard              # ~/cases"
    echo "    Demo studies:     atlas-dashboard --demo       # Atlas/demo-cases"
    echo "    Benchmarks:       atlas-dashboard --benchmarks"
    echo "    Custom root:      atlas-dashboard --cases-root /path/to/cases"
else
    warn "atlas-dashboard wrapper missing at $DASHBOARD_BIN_SRC"
fi

# Optional boot start + LAN listen — asked here, applied after .env/venv exist
# (step 5c) so ATLAS_DASHBOARD_BIND can be written and the unit can ExecStart.
if [ "$WITH_DASHBOARD_SERVICE" != 1 ]; then
    ask_yn "Start the dashboard automatically on boot?" n
    [ "$REPLY_YN" = 1 ] && WITH_DASHBOARD_SERVICE=1
fi
if [ "$WITH_DASHBOARD_LAN" != 1 ]; then
    ask_yn "Should the dashboard be configured to be available on the network (LAN, not the internet)?" n
    [ "$REPLY_YN" = 1 ] && WITH_DASHBOARD_LAN=1
fi
# Asked up front with the other optional-feature questions and applied at
# step 6, so the choice is made before the long venv install starts.
if [ "$WITH_FULL_TESTS" != 1 ]; then
    ask_yn "Also run the full developer test suite at the end? It takes several minutes on a workstation and 30 minutes or more on a small VM; a quick check runs either way." n
    [ "$REPLY_YN" = 1 ] && WITH_FULL_TESTS=1
fi


# ── 1d. Production cases root + layout migration ─────────────────────────────

step "Ensuring ~/cases is a real production case root"

# Target layout:
#   ~/cases/              — customer investigations (outside the repo)
#   Atlas/demo-cases/      — bundled example studies (in-repo)
#   Atlas/benchmarks/      — ground_truth grading sets (in-repo)
#   Atlas/cases → ~/cases  — one-release compat symlink (gitignored)
#
# Older installs had ~/cases → Atlas/cases (everything inside the repo). Migrate
# that inverted layout automatically when detected.

migrate_home_cases_layout() {
    local link_target
    if [ -L "$HOME/cases" ]; then
        link_target="$(readlink -f "$HOME/cases" 2>/dev/null || true)"
        if [ "$link_target" = "$ATLAS_DIR/cases" ] || [ "$link_target" = "$(readlink -f "$ATLAS_DIR/cases" 2>/dev/null)" ]; then
            if [ -d "$ATLAS_DIR/cases" ] && [ ! -L "$ATLAS_DIR/cases" ]; then
                warn "Migrating inverted layout: materializing ~/cases and splitting in-repo datasets"
                local staging="$ATLAS_DIR/_cases_migrate"
                mv "$ATLAS_DIR/cases" "$staging"
                rm -f "$HOME/cases"
                mkdir -p "$HOME/cases" "$ATLAS_DIR/demo-cases" "$ATLAS_DIR/benchmarks" "$ATLAS_DIR/share/.common"
                [ -d "$staging/.common" ] && mv "$staging/.common" "$HOME/cases/.common"
                # Production heuristics: dirs with evidence/ stay in ~/cases; known
                # ground_truth benchmarks go to benchmarks/; everything else → demo-cases.
                local d name
                for d in "$staging"/*/; do
                    [ -d "$d" ] || continue
                    name="$(basename "$d")"
                    if [ -d "$d/evidence" ] && [ "$(find "$d/evidence" -type f 2>/dev/null | head -1)" ]; then
                        mv "$d" "$HOME/cases/$name"
                    elif [ -f "$d/ground_truth.json" ]; then
                        mv "$d" "$ATLAS_DIR/benchmarks/$name"
                    else
                        mv "$d" "$ATLAS_DIR/demo-cases/$name"
                    fi
                done
                if [ -d "$HOME/cases/.common" ]; then
                    cp -a "$HOME/cases/.common/"*.json "$ATLAS_DIR/share/.common/" 2>/dev/null || true
                fi
                rm -rf "$staging"
                ok "Migrated production cases → ~/cases; demos/benchmarks under Atlas/"
            fi
        fi
    fi
    mkdir -p "$HOME/cases" "$ATLAS_DIR/demo-cases" "$ATLAS_DIR/benchmarks"
    # Compat: Atlas/cases → ~/cases (not committed; absolute target)
    if [ -L "$ATLAS_DIR/cases" ] || [ ! -e "$ATLAS_DIR/cases" ]; then
        ln -sfn "$HOME/cases" "$ATLAS_DIR/cases"
        ok "Compat symlink $ATLAS_DIR/cases → $HOME/cases"
    elif [ -d "$ATLAS_DIR/cases" ]; then
        warn "$ATLAS_DIR/cases is a real directory — leave it; prefer ~/cases for new investigations"
    fi
}
migrate_home_cases_layout

# Ensure XDG cache / history are real files under $HOME (not symlinks into the repo)
mkdir -p "$HOME/.cache/atlas"
if [ -L "$HOME/.cache/atlas" ]; then
    tmp=$(mktemp -d)
    cp -a "$HOME/.cache/atlas/." "$tmp/" 2>/dev/null || true
    rm -f "$HOME/.cache/atlas"
    mkdir -p "$HOME/.cache/atlas"
    cp -a "$tmp/." "$HOME/.cache/atlas/" 2>/dev/null || true
    rm -rf "$tmp" "$ATLAS_DIR/.cache"
    ok "Materialized ~/.cache/atlas (XDG)"
fi
if [ -L "$HOME/.atlas_history" ]; then
    if [ -f "$ATLAS_DIR/.atlas_history" ]; then
        cp -a "$ATLAS_DIR/.atlas_history" "$HOME/.atlas_history.tmp"
        rm -f "$HOME/.atlas_history"
        mv "$HOME/.atlas_history.tmp" "$HOME/.atlas_history"
        rm -f "$ATLAS_DIR/.atlas_history"
    else
        rm -f "$HOME/.atlas_history"
        : > "$HOME/.atlas_history"
    fi
    ok "Materialized ~/.atlas_history"
fi

# ── 1e. MITRE ATT&CK reference table ─────────────────────────────────────────

step "Installing MITRE ATT&CK reference table"

# The tables Atlas reads live under ~/cases/.common/ (tools/mitre/__init__.py);
# the repo ships them under share/.common/. A table the repo has updated —
# a new ATT&CK release rebuilt with tools/mitre/build_mitre_cache.py — must
# reach the machine, so each file is copied whenever it differs, not only
# when it is missing. The first copy used to be kept forever.
MITRE_SRC_DIR="$ATLAS_DIR/share/.common"
MITRE_DEST_DIR="$HOME/cases/.common"
mkdir -p "$MITRE_DEST_DIR"
if [ -f "$MITRE_SRC_DIR/mitre_techniques.json" ]; then
    MITRE_COPIED=0
    for src in "$MITRE_SRC_DIR"/mitre_*.json; do
        dest="$MITRE_DEST_DIR/$(basename "$src")"
        if [ ! -f "$dest" ] || ! cmp -s "$src" "$dest"; then
            cp "$src" "$dest"
            record_path file "$dest"
            MITRE_COPIED=$((MITRE_COPIED + 1))
        fi
    done
    MITRE_VER=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['_meta'].get('version','?'))" "$MITRE_SRC_DIR/mitre_techniques.json" 2>/dev/null || echo "?")
    if [ "$MITRE_COPIED" -gt 0 ]; then
        ok "MITRE ATT&CK tables ($MITRE_VER): $MITRE_COPIED file(s) updated → $MITRE_DEST_DIR/"
    else
        ok "MITRE ATT&CK tables ($MITRE_VER) already current at $MITRE_DEST_DIR/"
    fi
else
    warn "MITRE reference tables not found in repo (share/.common/); technique validation, attribution and derived recommendations will be no-ops"
fi

step "Bundled demo / benchmark datasets (in-repo)"
ok "Demos: $ATLAS_DIR/demo-cases/  — browse: ./dashboard.sh --demo"
ok "Benchmarks: $ATLAS_DIR/benchmarks/  — browse: ./dashboard.sh --benchmarks"
ok "Production investigations: $HOME/cases/  — browse: ./dashboard.sh"


# ── 2. Passwordless sudo for forensic tools (least privilege) ─────────────────

step "Configuring passwordless sudo for Atlas forensic tools"

ATLAS_SUDOERS_SCRIPT="$ATLAS_DIR/bin/atlas-sudoers"
ATLAS_SUDOERS_TEMPLATE="$ATLAS_DIR/share/atlas-sudoers.in"

if [ "$RUNNING_AS_ROOT" = 1 ]; then
    # A NOPASSWD grant is meaningless when the process already runs as root —
    # skip it outright rather than writing a no-op sudoers file.
    ok "Running as root — skipping sudoers grant (not needed)"
else
    PROCEED_SUDOERS=1
    if [ -f "$ATLAS_SUDOERS_TEMPLATE" ]; then
        echo "  The following least-privilege sudo rule is about to be installed"
        echo "  (NOT 'NOPASSWD: ALL' — see share/atlas-sudoers.in for the full"
        echo "  rationale and caveats):"
        echo ""
        grep -vE '^\s*#|^\s*$' "$ATLAS_SUDOERS_TEMPLATE" | sed 's/^/    /'
        echo ""
        ask_yn "Install this sudoers rule?" y
        PROCEED_SUDOERS="$REPLY_YN"
    fi
    if [ "$PROCEED_SUDOERS" != 1 ]; then
        warn "Skipped sudoers grant — mount/carve tools will prompt for a password or fail until you run: bin/atlas-sudoers"
    elif [ -x "$ATLAS_SUDOERS_SCRIPT" ] || { [ -f "$ATLAS_SUDOERS_SCRIPT" ] && chmod +x "$ATLAS_SUDOERS_SCRIPT"; }; then
        if "$ATLAS_SUDOERS_SCRIPT"; then
            MANIFEST_SUDOERS_FILE="/etc/sudoers.d/atlas-$(whoami)"
            ok "Passwordless sudo via $ATLAS_SUDOERS_SCRIPT → $MANIFEST_SUDOERS_FILE"
        else
            warn "atlas-sudoers failed — mount/carve tools will block until you run: bin/atlas-sudoers"
        fi
    else
        warn "Missing $ATLAS_SUDOERS_SCRIPT — cannot install sudoers"
    fi
fi

# ── 2b. Brain git hooks (contributor gate + public-remote leak guard) ─────────

step "Enabling brain git hooks"

# Route git hooks to the tracked .githooks/ dir so every clone gets both:
#   pre-commit  — limits durable brain changes to brain/CONTRIBUTORS.
#   pre-push    — blocks INTERNAL paths / branches from reaching the public
#                 GitHub remote (internal work stays on a private remote;
#                 GitHub gets a scrubbed snapshot via `atlas publish`).
if git -C "$ATLAS_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    git -C "$ATLAS_DIR" config core.hooksPath .githooks
    ok "core.hooksPath = .githooks (pre-commit contributor gate + pre-push public-leak guard)"
else
    warn "Not a git checkout — skipping hook setup; brain commit/push gating is off"
fi

# A previous install may have left atlas-dashboard.service enabled and
# running. Rebuilding .venv (make_venv below does `rm -rf .venv` when pip is
# missing/broken) out from under that process crashes it into a restart loop
# on the now-deleted interpreter, and it can win the race back to "running"
# on a stale environment before step 5c finishes writing ATLAS_DASHBOARD_BIND
# and reinstalling the unit — the service then looks up but is silently
# still bound to 127.0.0.1 HTTP. Stop it first; restart it once .venv and
# .env are both settled (step 5c does this when it re-enables the unit, the
# catch-all below covers every path that doesn't).
DASH_SERVICE_WAS_ACTIVE=0
if [ -d /run/systemd/system ] \
        && systemctl is-active --quiet atlas-dashboard.service 2>/dev/null; then
    DASH_SERVICE_WAS_ACTIVE=1
    step "Stopping atlas-dashboard.service before rebuilding the Python environment"
    sudo systemctl stop atlas-dashboard.service
fi

# ── 3. Python virtual environment ─────────────────────────────────────────────

step "Setting up Python environment"

# A partial venv from a previous failed run (e.g. one that died at ensurepip)
# leaves the directory but no working pip — treat that as needing recreation,
# otherwise the pip steps below fail with a confusing error.
make_venv() { [ -d "$VENV_DIR" ] && rm -rf "$VENV_DIR"; python3 -m venv "$VENV_DIR" 2>/dev/null; }

if [ ! -x "$VENV_DIR/bin/pip" ]; then
    if ! make_venv; then
        # ensurepip is missing. The generic python3-venv metapackage tracks the
        # apt-default python, which on a multi-python box (e.g. SIFT's python3.12)
        # differs from the `python3` command — so install the venv package matching
        # THIS python3 by version, then retry.
        PYV="$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
        warn "venv creation failed (ensurepip missing) — installing python${PYV}-venv to match python3 $PYV"
        apt_install_new "python${PYV}-venv" python3-pip 2>/dev/null \
            || apt_install_new python3-venv python3-pip 2>/dev/null \
            || true
        if ! make_venv; then
            fail "Failed to create venv even after installing python${PYV}-venv. Install it manually and re-run: sudo apt-get install -y python${PYV}-venv python3-pip"
        fi
    fi
    ok "Created venv at $VENV_DIR"
else
    ok "Venv already exists at $VENV_DIR"
fi

# Keep ~/.venv as a symlink so older docs / shells that source ~/.venv still work.
if [ -e "$HOME/.venv" ] && [ ! -L "$HOME/.venv" ]; then
    warn "Replacing non-symlink $HOME/.venv with link to $VENV_DIR"
    rm -rf "$HOME/.venv"
fi
ln -sfn "$VENV_DIR" "$HOME/.venv"
ok "Symlinked $HOME/.venv → $VENV_DIR"

"$VENV_DIR/bin/pip" install --quiet --upgrade pip
# Do NOT use --quiet here: flare-capa/flare-floss (and yara-python, which compiles
# C) are large and can take several minutes. With --quiet the step produces zero
# output and looks hung; show pip's normal progress instead.
info "Installing Python dependencies — this can take several minutes (flare-capa / flare-floss / yara-python / volatility3 are large). Progress shown below."
"$VENV_DIR/bin/pip" install -r "$ATLAS_DIR/requirements.txt"
"$VENV_DIR/bin/pip" install -r "$ATLAS_DIR/requirements-dev.txt"
ok "Dependencies installed (fastmcp, httpx, yara-python, volatility3, flare-capa, flare-floss, oletools, pytest)"

# Symlink the venv's `vol` to /usr/local/bin/vol — see step 1cv above.
# core/paths.py:vol3_bin() checks PATH first now, so this is belt-and-suspenders
# for anything (docs, muscle memory) expecting the exact SIFT path.
if [ -x "$VENV_DIR/bin/vol" ]; then
    if sudo ln -sfn "$VENV_DIR/bin/vol" /usr/local/bin/vol 2>/dev/null; then
        record_path symlink /usr/local/bin/vol
        ok "Volatility 3 → /usr/local/bin/vol (symlinked from venv)"
    else
        ok "Volatility 3 installed in venv; on PATH as 'vol' when the venv is active (symlink to /usr/local/bin/vol skipped — no sudo)"
    fi
else
    warn "volatility3's 'vol' console-script not found in venv after install — vol.* tools will report unavailable"
fi

# Retry Plaso-via-pip here if step 1cw deferred it (venv didn't exist yet).
if ! command -v log2timeline.py &>/dev/null && ! [ -x "$VENV_DIR/bin/log2timeline.py" ]; then
    if "$VENV_DIR/bin/pip" install --quiet plaso 2>/dev/null; then
        ok "Installed Plaso via pip (deferred from step 1cw)"
    fi
fi

# ── 3a. INDXParse ($I30 slack parsing) ──────────────────────────────────────

# install_indxparse — INDXParse at the pinned commit in the venv, proven to
# start. Upstream ships it as a Python package whose commands are console
# scripts (INDXParse.py, MFTINDX.py, …); pip installs the commit
# (INDXPARSE_REF, install-versions.env) into the venv, where each script gets
# the venv's interpreter line and core.paths.tool_program finds it. pip
# records the commit in the distribution's direct_url.json, which the pin
# check reads. Returns 0 when the pinned INDXParse.py starts. Optional: every
# failure is a warning.
install_indxparse() {
    local spec="indxparse @ git+https://github.com/williballenthin/INDXParse@${INDXPARSE_REF}"
    local script="$VENV_DIR/bin/INDXParse.py" at log effect
    at=$("$VENV_DIR/bin/python" -c 'import json, importlib.metadata as m; print(json.loads(m.distribution("indxparse").read_text("direct_url.json") or "{}").get("vcs_info", {}).get("commit_id", ""))' 2>/dev/null) || at=""
    if [ "$at" = "$INDXPARSE_REF" ] && [ -x "$script" ]; then
        ok "INDXParse already installed @ ${INDXPARSE_REF:0:12}"
    else
        log="$(mktemp)"
        # pip calls an installed indxparse of the same version satisfied
        # whichever commit it came from, so the pinned commit is forced in
        # first; the second call then resolves its dependencies.
        if ! "$VENV_DIR/bin/pip" install --force-reinstall --no-deps "$spec" &>"$log"; then
            if [ -x "$script" ]; then
                effect="the INDXParse.py already in the venv stays in use"
            else
                effect="tsk.tsk_indxparse reports it missing"
            fi
            warn "Could not install INDXParse @ ${INDXPARSE_REF:0:12} (offline, git missing, or the pinned commit is gone — see install-versions.env) — $effect. pip said:"
            tail -5 "$log" | sed 's/^/    /'
            rm -f "$log"
            return 1
        fi
        if "$VENV_DIR/bin/pip" install "$spec" &>>"$log"; then
            ok "Installed INDXParse @ ${INDXPARSE_REF:0:12} → $script"
        else
            warn "Installed INDXParse @ ${INDXPARSE_REF:0:12}, but pip could not add the dependencies of its other scripts (jinja2); INDXParse.py does not use them. pip said:"
            tail -5 "$log" | sed 's/^/    /'
        fi
        rm -f "$log"
    fi
    if ! "$script" -h >/dev/null 2>&1; then
        warn "INDXParse.py does not start — check: $script -h"
        return 1
    fi
}

# remove_unrunnable_indxparse — a /usr/local/bin/INDXParse.py whose first
# bytes are not "#!" is upstream's module copied as a file: the kernel cannot
# execute it, and a shell that runs it reads the Python as shell commands. It
# goes once the venv's copy has started, and leaves the manifest with it. A
# file that starts with "#!" is a working install and stays.
remove_unrunnable_indxparse() {
    local stale="/usr/local/bin/INDXParse.py"
    [ -f "$stale" ] || return 0
    [ "$(head -c 2 "$stale" 2>/dev/null)" = "#!" ] && return 0
    if sudo rm -f "$stale" && [ ! -e "$stale" ]; then
        forget_path "$stale"
        info "Removed $stale — a copy without an interpreter line cannot be executed; $VENV_DIR/bin/INDXParse.py replaces it"
    else
        warn "Could not remove $stale, which cannot be executed — remove it by hand: sudo rm $stale"
    fi
}

step "Installing INDXParse (NTFS \$I30 slack parsing, optional)"
if install_indxparse; then
    remove_unrunnable_indxparse
fi

# ── 3b. Hayabusa (Sigma triage of Windows event logs) ────────────────────────

step "Installing DensityScout (file entropy triage)"
# Prebuilt Linux binary from CERT.at; misc.densityscout_scan resolves it on
# PATH. Optional: a failed download is a warning, not an abort.
DENSITYSCOUT_BIN="/usr/local/bin/densityscout"
if command -v densityscout &>/dev/null; then
    ok "densityscout already installed at $(command -v densityscout)"
else
    DS_URL="https://www.cert.at/media/files/downloads/software/densityscout/files/densityscout_build_45_linux.zip"
    DS_TMP=$(mktemp -d)
    if curl -fsSL "$DS_URL" -o "$DS_TMP/ds.zip" 2>/dev/null && unzip -q "$DS_TMP/ds.zip" -d "$DS_TMP" 2>/dev/null \
            && [ -f "$DS_TMP/lin64/densityscout" ]; then
        sudo install -m 0755 "$DS_TMP/lin64/densityscout" "$DENSITYSCOUT_BIN"
        record_path file "$DENSITYSCOUT_BIN"
        ok "Installed densityscout → $DENSITYSCOUT_BIN"
    else
        warn "Could not fetch DensityScout (offline, or the download moved) — misc.densityscout_scan will report it as not installed"
    fi
    rm -rf "$DS_TMP"
fi
# usn.py (usnparser) and pefile install with requirements.txt in the pip step;
# misc.usnparser_parse and misc.pe_scanner use them from the venv.

step "Building jphide/jpseek (JPEG steganography, optional)"
# No distribution packages the jphs tools. The source bundles its own
# libjpeg (jpeg-8a), built first and linked statically; its output open()
# lacks a file mode, which current compilers refuse, so the mode is added
# before building. Optional: steg.steg_extract still reads steghide and
# outguess embeddings without it.
JPSEEK_BIN="/usr/local/bin/jpseek"
if command -v jpseek &>/dev/null; then
    ok "jpseek already installed at $(command -v jpseek)"
else
    JPHS_TMP=$(mktemp -d)
    JPHS_LOG="$JPHS_TMP/build.log"
    if sudo apt-get install -y build-essential &>>"$JPHS_LOG" \
        && git clone --quiet https://github.com/h3xx/jphs "$JPHS_TMP/jphs" &>>"$JPHS_LOG" \
        && git -C "$JPHS_TMP/jphs" checkout --quiet "$JPHS_REF" &>>"$JPHS_LOG" \
        && sed -i "s/O_WRONLY|O_TRUNC|O_CREAT)/O_WRONLY|O_TRUNC|O_CREAT, 0644)/" "$JPHS_TMP/jphs/jpseek.c" \
        && (cd "$JPHS_TMP/jphs/jpeg-8a" && ./configure && make) &>>"$JPHS_LOG" \
        && make -C "$JPHS_TMP/jphs" all LDFLAGS="-L./jpeg-8a/.libs" LDLIBS="-ljpeg" &>>"$JPHS_LOG" \
        && [ -f "$JPHS_TMP/jphs/jpseek" ]; then
        sudo install -m 0755 "$JPHS_TMP/jphs/jpseek" "$JPSEEK_BIN"
        sudo install -m 0755 "$JPHS_TMP/jphs/jphide" /usr/local/bin/jphide
        record_path file "$JPSEEK_BIN"
        record_path file /usr/local/bin/jphide
        ok "Built jpseek and jphide → /usr/local/bin"
        rm -rf "$JPHS_TMP"
    else
        warn "Could not build jphs (log: $JPHS_LOG) — steg.steg_extract reads steghide and outguess embeddings and names jpseek as missing"
    fi
fi

step "Installing the Velociraptor client binary (velo.* live queries, optional)"
# The velo.* tools drive a Velociraptor server through this binary and an
# API config the operator issues (ATLAS_VELO_API_CONFIG); the binary is the
# part install.sh can provide. Optional: without a server there is nothing
# to query, and every other tool is unaffected.
VELO_BIN="/usr/local/bin/velociraptor"
if command -v velociraptor &>/dev/null; then
    ok "velociraptor already installed at $(command -v velociraptor)"
else
    case "$(uname -m)" in
        x86_64) VELO_ARCH="amd64" ;;
        aarch64) VELO_ARCH="arm64" ;;
        *) VELO_ARCH="" ;;
    esac
    VELO_URL="https://github.com/Velocidex/velociraptor/releases/download/v${VELOCIRAPTOR_VERSION}/velociraptor-v${VELOCIRAPTOR_VERSION}-linux-${VELO_ARCH}"
    VELO_TMP=$(mktemp -d)
    if [ -n "$VELO_ARCH" ] && curl -fsSL "$VELO_URL" -o "$VELO_TMP/velociraptor" 2>/dev/null \
            && [ -s "$VELO_TMP/velociraptor" ]; then
        sudo install -m 0755 "$VELO_TMP/velociraptor" "$VELO_BIN"
        record_path file "$VELO_BIN"
        ok "Installed velociraptor ${VELOCIRAPTOR_VERSION} → $VELO_BIN (an API config is still needed: velociraptor config api_client)"
    else
        warn "Could not fetch velociraptor ${VELOCIRAPTOR_VERSION} for $(uname -m) (offline, or no build for this architecture) — velo.* tools stay unavailable"
    fi
    rm -rf "$VELO_TMP"
fi

step "Installing Detect It Easy (packer / compiler identification, optional)"
# No distribution packages DIE. Upstream publishes one .deb per distribution
# release, named die_<version>_<Distro>_<Release>_amd64.deb, so the asset is
# built from /etc/os-release rather than guessed. Optional throughout: a
# release without an asset for this distribution, or no network, is a warning
# — misc.pe_scanner still reports section entropy and packer hints, which is
# what most cases need DIE for.
if command -v diec &>/dev/null || command -v die &>/dev/null; then
    ok "Detect It Easy already installed ($(command -v diec || command -v die))"
else
    # Ask the pinned release which builds actually exist, rather than
    # guessing a file name: upstream adds distribution releases over time
    # (16.04 through 26.04 today), and a guess is wrong the moment they do.
    # An exact match wins; otherwise the newest build older than this system,
    # which is what a Ubuntu 25.04 or Debian 13 box needs. The *version* stays
    # pinned in install-versions.env — only the asset choice is discovered.
    DIE_ASSET=$(curl -fsSL --max-time 20 \
        "https://api.github.com/repos/horsicq/DIE-engine/releases/tags/${DIE_VERSION}" 2>/dev/null \
        | python3 -c '
import json, re, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
family = {"ubuntu": "Ubuntu", "debian": "Debian", "kali": "Kali"}.get(sys.argv[1], "")
if not family:
    sys.exit(0)
want = sys.argv[2]
pattern = re.compile(r"^die_.*_%s_([0-9.]+)_amd64\.deb$" % family)
def key(v):
    return [int(x) for x in v.split(".") if x.isdigit()]
builds = []
for asset in data.get("assets", []):
    m = pattern.match(asset["name"])
    if m:
        builds.append((key(m.group(1)), asset["name"]))
exact = [n for k, n in builds if k == key(want)]
if exact:
    print(exact[0])
else:
    older = sorted(k_n for k_n in builds if k_n[0] <= key(want))
    if older:
        print(older[-1][1])
' "$OS_ID" "$OS_VERSION" 2>/dev/null)
    # No network / no API: fall back to the name upstream uses today.
    if [ -z "$DIE_ASSET" ]; then
        case "$OS_ID" in
            ubuntu) DIE_ASSET="die_${DIE_VERSION}_Ubuntu_${OS_VERSION}_amd64.deb" ;;
            debian) DIE_ASSET="die_${DIE_VERSION}_Debian_${OS_VERSION%%.*}_amd64.deb" ;;
            kali)   DIE_ASSET="die_${DIE_VERSION}_Kali_${OS_VERSION}_amd64.deb" ;;
        esac
    fi
    if [ -z "$DIE_ASSET" ]; then
        warn "No Detect It Easy build for $OS_ID $OS_VERSION — bin.diec_scan stays optional; misc.pe_scanner covers packer hints and section entropy"
    else
        DIE_URL="https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/${DIE_ASSET}"
        DIE_TMP=$(mktemp -d)
        if curl -fsSL "$DIE_URL" -o "$DIE_TMP/$DIE_ASSET" 2>/dev/null; then
            if sudo apt-get install -y "$DIE_TMP/$DIE_ASSET" &>/dev/null \
                    || { sudo dpkg -i "$DIE_TMP/$DIE_ASSET" &>/dev/null; sudo apt-get -f install -y &>/dev/null; }; then
                record_path file "/usr/bin/diec"
                ok "Installed Detect It Easy ${DIE_VERSION} ($(command -v diec || command -v die || echo 'see /usr/bin'))"
            else
                warn "Detect It Easy package downloaded but would not install — bin.diec_scan stays optional"
            fi
        else
            warn "No Detect It Easy asset at $DIE_URL (release ${DIE_VERSION} may not build for $OS_ID $OS_VERSION) — bin.diec_scan stays optional"
        fi
        rm -rf "$DIE_TMP"
    fi
fi

step "Installing the Didier Stevens PDF tools (pdfid, pdf-parser)"
# misc.pdfid_scan / misc.pdf_parser_analyze resolve these through
# core.paths.tool_program, so anywhere on PATH works; /usr/local/bin keeps
# them next to the other forensic programs. Optional: a failed clone is a
# warning and the two tools then report themselves as not installed.
if command -v pdfid.py &>/dev/null && command -v pdf-parser.py &>/dev/null; then
    ok "pdfid.py and pdf-parser.py already installed"
else
    DS_SUITE_DIR="/opt/didierstevens"
    if sudo git clone --depth 1 https://github.com/DidierStevens/DidierStevensSuite.git \
            "$DS_SUITE_DIR" &>/dev/null || [ -d "$DS_SUITE_DIR" ]; then
        for _tool in pdfid.py pdf-parser.py; do
            if [ -f "$DS_SUITE_DIR/$_tool" ]; then
                sudo chmod +x "$DS_SUITE_DIR/$_tool"
                sudo ln -sf "$DS_SUITE_DIR/$_tool" "/usr/local/bin/$_tool"
                record_path file "/usr/local/bin/$_tool"
                ok "Installed $_tool → /usr/local/bin/$_tool"
            else
                warn "$_tool missing from the Didier Stevens suite checkout"
            fi
        done
        record_path dir "$DS_SUITE_DIR"
    else
        warn "Could not fetch the Didier Stevens suite (offline?) — misc.pdfid_scan and misc.pdf_parser_analyze will report themselves as not installed"
    fi
fi

# pyhindsight provides the `hindsight` console script in the venv, which
# misc.hindsight_chrome resolves through PATH; it ships in requirements.txt.

step "Installing Hayabusa (Sigma triage of Windows event logs)"

HAYABUSA_HOME="$HOME/.local/share/atlas/hayabusa"
# HAYABUSA_VERSION comes from install-versions.env (sourced above)

if [ -d "$HAYABUSA_HOME" ] && [ -n "$(find "$HAYABUSA_HOME" -maxdepth 1 -name 'hayabusa*' -print -quit 2>/dev/null)" ]; then
    ok "Hayabusa already installed at $HAYABUSA_HOME"
else
    # The all-platforms release zip carries the Linux binaries beside
    # rules/ and config/, so one download covers everything hayabusa.*
    # needs.
    HAYABUSA_URL="https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-all-platforms.zip"
    HAYABUSA_TMP=$(mktemp -d)
    if curl -fsSL "$HAYABUSA_URL" -o "$HAYABUSA_TMP/hayabusa.zip" 2>/dev/null; then
        if ! unzip -q "$HAYABUSA_TMP/hayabusa.zip" -d "$HAYABUSA_TMP" 2>/dev/null; then
            warn "Hayabusa archive corrupt — skipping (Atlas works without it; hayabusa.* tools will report unavailable)"
        else
            # Prefer the musl build (statically linked — most portable across
            # host libc versions); fall back to the gnu build.
            HAYABUSA_SRC_BIN=""
            for cand in "$HAYABUSA_TMP/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl" \
                        "$HAYABUSA_TMP/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu"; do
                if [ -f "$cand" ]; then HAYABUSA_SRC_BIN="$cand"; break; fi
            done
            if [ -z "$HAYABUSA_SRC_BIN" ] || [ ! -d "$HAYABUSA_TMP/rules" ]; then
                warn "Hayabusa archive layout unexpected; skipping"
            else
                mkdir -p "$HAYABUSA_HOME"
                record_path dir "$HAYABUSA_HOME"
                install -m 0755 "$HAYABUSA_SRC_BIN" "$HAYABUSA_HOME/$(basename "$HAYABUSA_SRC_BIN")"
                cp -r "$HAYABUSA_TMP/rules" "$HAYABUSA_HOME/rules"
                if [ -d "$HAYABUSA_TMP/config" ]; then
                    cp -r "$HAYABUSA_TMP/config" "$HAYABUSA_HOME/config"
                fi
                RULE_COUNT=$(find "$HAYABUSA_HOME/rules" -name '*.yml' | wc -l)
                ok "Installed Hayabusa v${HAYABUSA_VERSION} → $HAYABUSA_HOME ($RULE_COUNT sigma rules)"
            fi
        fi
    else
        warn "Could not download Hayabusa (offline?). Skip — Atlas works without it; hayabusa.* tools will report unavailable."
    fi
    rm -rf "$HAYABUSA_TMP"
fi

# ── 4. Environment file ───────────────────────────────────────────────────────

step "Configuring environment"

if [ ! -f "$ATLAS_DIR/.env" ]; then
    cp "$ATLAS_DIR/.env.example" "$ATLAS_DIR/.env"
    ok "Created .env from .env.example"
else
    ok ".env already exists — skipping"
fi

# LLM backend: offer the interactive wizard (bin/atlas provider setup) rather
# than a narrow inline prompt — it covers the T-Systems LLM Hub (recommended:
# z.ai GLM-5.2, already .env.example's default model), OpenAI, a local/
# self-hosted OpenAI-compatible server, or any other gateway, tests the
# connection live, and points every model role at the result. See
# docs/llm.md and core/llm_setup.py.
if [ "$ASSUME_YES" != 1 ] && [ -t 0 ]; then
    ask_yn "Configure an LLM backend now with the interactive wizard (bin/atlas provider setup)?" y
    if [ "$REPLY_YN" = 1 ]; then
        "$ATLAS_DIR/bin/atlas" provider setup || \
            warn "Wizard exited without finishing — re-run any time: bin/atlas provider setup"
    else
        warn "Skipped — configure later with: bin/atlas provider setup (or edit .env by hand, see docs/llm.md). REQUIRED for a full-quality run."
    fi
else
    warn "Non-interactive install — configure an LLM backend with: bin/atlas provider setup (or edit .env by hand, see docs/llm.md). REQUIRED for a full-quality run."
fi

# Optional OSINT enrichment API keys. Unlike the LLM backend above, none of
# these are required — enrichment.* tools (tools/enrichment.py) report
# themselves unavailable without a key, the same graceful-degradation
# posture as every other optional capability in this installer. Offered here
# so a first-time install doesn't leave someone unaware these exist; declined
# by default (ask_yn ... n) since most installs won't have accounts for all
# of them. bin/atlas-secret writes to .env (not the keyring) — --env is the
# right default here since it works with no Secret Service / D-Bus session
# (e.g. a headless VM or container), which is exactly the kind of host this
# step needs to not assume away.
if [ "$ASSUME_YES" != 1 ] && [ -t 0 ]; then
    ask_yn "Configure optional OSINT enrichment API keys now (VirusTotal, AbuseIPDB, OTX, URLScan, MISP)?" n
    if [ "$REPLY_YN" = 1 ]; then
        declare -A OSINT_KEY_DESC=(
            [VIRUSTOTAL_API_KEY]="VirusTotal — file/hash/URL/IP reputation"
            [ABUSEIPDB_API_KEY]="AbuseIPDB — IP abuse-confidence reports"
            [OTX_API_KEY]="AlienVault OTX — pulses, tags, malware families for an indicator"
            [URLSCAN_API_KEY]="urlscan.io — URL scan submission/lookup"
            [MISP_URL]="MISP instance URL — your own threat-intel platform, if you run one"
            [MISP_API_KEY]="MISP API key (pairs with MISP_URL above)"
        )
        for key in VIRUSTOTAL_API_KEY ABUSEIPDB_API_KEY OTX_API_KEY URLSCAN_API_KEY MISP_URL MISP_API_KEY; do
            ask_yn "  Set $key (${OSINT_KEY_DESC[$key]})?" n
            if [ "$REPLY_YN" = 1 ]; then
                "$ATLAS_DIR/bin/atlas-secret" set --env "$key" || \
                    warn "Could not set $key — configure later with: bin/atlas-secret set --env $key"
            fi
        done
    else
        warn "Skipped — configure any time with: bin/atlas-secret set --env <KEY> (VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY, URLSCAN_API_KEY, MISP_URL, MISP_API_KEY). All optional."
    fi
fi

# ── 5. Hub playbook smoke (assembled in-process by bin/atlas) ──────────────────

step "Verifying hub/playbook assembly"

if ( cd "$ATLAS_DIR" && "$VENV_DIR/bin/python" -m agent.playbook -o /tmp/atlas-playbook-install-check.md ) \
        2>/dev/null \
    || ( cd "$ATLAS_DIR" && PYTHONPATH="$ATLAS_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -m agent.playbook -o /tmp/atlas-playbook-install-check.md ) \
        2>/dev/null; then
    ok "Playbook assembles from hub/ENTRY.md + hub/playbook/"
    rm -f /tmp/atlas-playbook-install-check.md
else
    fail "Playbook assemble failed — check hub/playbook/MANIFEST and hub/ENTRY.md"
fi

ok "MCP tools load in-process via bin/atlas (no external MCP registration)"

# ── 5b. Optional SMB network share (needs the venv from step 3 and the
# sudoers grant from step 2 — both must already be in place) ─────────────────
if [ "$WITH_NETWORK_SHARE" = 1 ] && [ -n "$MANIFEST_SUDOERS_FILE" ]; then
    step "Enabling the SMB network share"
    if ( cd "$ATLAS_DIR" && "$VENV_DIR/bin/python" -m agent.cli share enable ); then
        MANIFEST_FLAG_SMB_SHARE=1
        ok "Share enabled — set a Samba password with: bin/atlas share passwd"
    else
        warn "Could not enable the network share — check 'bin/atlas share status', then run 'bin/atlas share enable' manually"
    fi
elif [ "$WITH_NETWORK_SHARE" = 1 ]; then
    warn "Network share requested but the sudoers grant was skipped — run 'bin/atlas-sudoers' then 'bin/atlas share enable' manually"
fi

# ── 5c. Optional dashboard LAN bind + boot service ───────────────────────────
# Asked at step 1cc; applied here because .env (step 4) and .venv (step 3)
# must already exist. First-admin signup stays on the dashboard itself.
if [ "$WITH_DASHBOARD_LAN" = 1 ]; then
    step "Configuring dashboard LAN listen (HTTPS on 0.0.0.0)"
    if [ -f "$ATLAS_DIR/.env" ]; then
        if ( cd "$ATLAS_DIR" && ATLAS_ENV="$ATLAS_DIR/.env" \
                "$VENV_DIR/bin/python" -c \
                'import os; from core.envfile import set_values; set_values(os.environ["ATLAS_ENV"], {"ATLAS_DASHBOARD_BIND": "0.0.0.0"})' ); then
            ok "Wrote ATLAS_DASHBOARD_BIND=0.0.0.0 to .env — dashboard is HTTPS on all interfaces. Restrict port 8765 to your LAN; Atlas does not open the firewall. First visit creates the admin account."
        else
            warn "Could not write ATLAS_DASHBOARD_BIND to .env — set it by hand and restart the dashboard"
        fi
    else
        warn ".env missing — set ATLAS_DASHBOARD_BIND=0.0.0.0 in it once it exists"
    fi
fi
if [ "$WITH_DASHBOARD_SERVICE" = 1 ] && [ "$RUNNING_AS_ROOT" = 1 ]; then
    warn "Running as root — skipping the dashboard boot service (it must run as the analyst account, not root). Re-run install.sh as that user, or: ./install.sh --with-dashboard-service"
    WITH_DASHBOARD_SERVICE=0
fi
if [ "$WITH_DASHBOARD_SERVICE" = 1 ]; then
    step "Installing dashboard boot service"
    if [ ! -d /run/systemd/system ]; then
        warn "systemd is not PID 1 on this host (container?) — skipping the boot service. Start the dashboard with: atlas-dashboard"
    elif [ ! -f "$ATLAS_DIR/share/atlas-dashboard.service.in" ]; then
        warn "share/atlas-dashboard.service.in missing — cannot install the boot service"
    else
        DASH_UNIT_DEST="/etc/systemd/system/atlas-dashboard.service"
        DASH_VENV_PY="$VENV_DIR/bin/python"
        [ -x "$DASH_VENV_PY" ] || DASH_VENV_PY="$VENV_DIR/bin/python3"
        if ! "$DASH_VENV_PY" -c "import argon2, dashboard.serve" 2>/dev/null; then
            warn "Venv at $VENV_DIR is missing dependencies (import argon2, dashboard.serve failed) — not enabling atlas-dashboard.service on a broken environment. Re-run: $VENV_DIR/bin/pip install -r requirements.txt, then ./install.sh --with-dashboard-service again"
        else
        DASH_UNIT_TMP="$(mktemp)"
        # Paths may contain '&' rarely; sed replacement is otherwise the same
        # @USER@ substitution atlas-sudoers already uses.
        sed -e "s|@USER@|$(whoami)|g" \
            -e "s|@GROUP@|$(id -gn)|g" \
            -e "s|@HOME@|${HOME}|g" \
            -e "s|@ATLAS_DIR@|${ATLAS_DIR}|g" \
            -e "s|@VENV_PY@|${DASH_VENV_PY}|g" \
            -e "s|@VENV_BIN@|$(dirname "${DASH_VENV_PY}")|g" \
            "$ATLAS_DIR/share/atlas-dashboard.service.in" > "$DASH_UNIT_TMP"
        # Five failed starts inside the unit's start-limit window leave it
        # failed until reset; a rerun that repaired the cause must start it.
        if sudo install -m 0644 "$DASH_UNIT_TMP" "$DASH_UNIT_DEST" \
                && sudo systemctl daemon-reload \
                && { sudo systemctl reset-failed atlas-dashboard.service 2>/dev/null || true; } \
                && sudo systemctl enable --now atlas-dashboard.service; then
            record_path file "$DASH_UNIT_DEST"
            MANIFEST_FLAG_DASHBOARD_SERVICE=1
            ok "Dashboard service enabled — starts on boot (systemctl status atlas-dashboard)"
            if [ "$WITH_DASHBOARD_LAN" = 1 ] && [ ! -f /etc/atlas/dashboard/tls.crt ]; then
                warn "No org TLS cert found — the service will generate a self-signed one on first start. Verify it before trusting the browser warning: journalctl -u atlas-dashboard | grep fingerprint"
            fi
        else
            warn "Could not enable atlas-dashboard.service — install the unit from share/atlas-dashboard.service.in by hand"
        fi
        rm -f "$DASH_UNIT_TMP"
        fi
    fi
fi

# enable --now above only starts the unit if it was NOT already active — it
# is a silent no-op on an already-running service (systemd semantics), which
# is exactly the scenario that stopped it before step 3. Anything left
# stopped from that point on (LAN-only reconfigure, service already
# installed from a prior run, etc.) needs to be brought back up here, now
# that .venv and .env have both settled.
if [ "$DASH_SERVICE_WAS_ACTIVE" = 1 ] && [ -d /run/systemd/system ] \
        && ! systemctl is-active --quiet atlas-dashboard.service 2>/dev/null; then
    step "Restarting atlas-dashboard.service (stopped earlier for the venv rebuild)"
    sudo systemctl reset-failed atlas-dashboard.service 2>/dev/null || true
    if sudo systemctl start atlas-dashboard.service; then
        ok "atlas-dashboard.service restarted"
    else
        warn "Could not restart atlas-dashboard.service — start it by hand: sudo systemctl start atlas-dashboard.service"
    fi
fi

# ── 6. Verify ─────────────────────────────────────────────────────────────────

step "Running post-install check"

cd "$ATLAS_DIR"
# The install is already complete by this point — a failing test should not abort
# the script under `set -e` and hide the "Atlas is ready" banner. Warn instead.
# The quick check is the tests marked install_smoke (pytest.ini): every CLI
# command and launcher, every tool module imported, tool discovery through the
# MCP SDK, and the dashboard serving its pages over TLS and a real sign-in.
# Seconds, not the full suite's minutes.
# Coverage is a developer measurement; --no-cov keeps its table out of the log.
if "$VENV_DIR/bin/python3" -m pytest tests/ -m install_smoke -q --tb=short --no-cov; then
    ok "Post-install check passed"
else
    rc=$?
    warn "Post-install check failed (exit $rc) — the install itself is complete; review the output above before relying on this build"
fi

if [ "$WITH_FULL_TESTS" = 1 ]; then
    step "Running the full test suite (several minutes on a workstation, 30 minutes or more on a small VM)"
    if "$VENV_DIR/bin/python3" -m pytest tests/ -q --tb=short --no-cov; then
        ok "Full test suite passed"
    else
        rc=$?
        warn "Full test suite reported failures (exit $rc) — the install itself is complete; review the output above"
    fi
else
    info "Full test suite skipped — run it any time with: cd $ATLAS_DIR && .venv/bin/python3 -m pytest tests/ -q --no-cov (or re-run ./install.sh --with-full-tests)"
fi

# ── 7. Manifest ───────────────────────────────────────────────────────────────

step "Checking every tool's program"
# The last word on what this install produced. Two tools were advertised for
# months with a program nobody had installed; the report this writes is what
# the dashboard's Tool health board and `atlas run` read, so an install that
# half-succeeded says so instead of surfacing later as a failed tool call.
HEALTH_PY="$VENV_DIR/bin/python"
[ -x "$HEALTH_PY" ] || HEALTH_PY="$VENV_DIR/bin/python3"
if (cd "$ATLAS_DIR" && "$HEALTH_PY" -m core.tool_health --write-install-report) 2>/dev/null; then
    # A heredoc inside a command substitution cannot carry a trailing `||`
    # — bash parses it as a syntax error. One-liner instead.
    TOOL_PROBLEMS=$(cd "$ATLAS_DIR" && "$HEALTH_PY" -c \
        'from core.tool_health import problems; print(len(problems()))' \
        2>/dev/null) || TOOL_PROBLEMS="?"
    if [ "${TOOL_PROBLEMS}" = "0" ]; then
        ok "Every declared tool program is present"
    else
        warn "${TOOL_PROBLEMS} tool program(s) missing or retired — see the dashboard's Settings → Tool health, or run: $HEALTH_PY -m core.tool_health"
    fi
else
    warn "Could not write the tool report — run $HEALTH_PY -m core.tool_health to see tool status"
fi

step "Recording install manifest"
MANIFEST_WRITTEN=1
write_manifest || true

# ── Done ──────────────────────────────────────────────────────────────────────

if [ "${#INSTALL_WARNINGS[@]}" -gt 0 ]; then
    echo ""
    echo -e "${RED}  ══════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  ${#INSTALL_WARNINGS[@]} warning(s) during install — read before relying on this build:${NC}"
    echo -e "${RED}  ══════════════════════════════════════════════════════════════${NC}"
    i=0
    for w in "${INSTALL_WARNINGS[@]}"; do
        i=$((i + 1))
        echo -e "${RED}  ${i}. ${NC}$w"
    done
    echo -e "${RED}  ══════════════════════════════════════════════════════════════${NC}"
fi

echo ""
echo -e "${GREEN}  Atlas is ready.${NC}"
echo ""
echo "  Next steps:"
echo "    1. No LLM backend configured yet? Run: bin/atlas provider setup"
echo "       REQUIRED for a full-quality run — powers the analyst, the reason.*"
echo "       reviewer, and the dair.* director. Recommended: Telekom LLM Hub with"
echo "       z.ai GLM-5.2 (the wizard marks this option recommended) — OpenAI,"
echo "       a local/self-hosted server, and any other gateway are equally"
echo "       supported. See docs/llm.md. (VirusTotal / AbuseIPDB keys are"
echo "       separate and optional — bin/atlas-secret set VIRUSTOTAL_API_KEY.)"
echo ""
echo "  Browse investigations:"
echo "    ./dashboard.sh                 # production ~/cases (http://127.0.0.1:8765)"
echo "    ./dashboard.sh --demo          # bundled demo-cases/"
echo "    ./dashboard.sh --benchmarks    # ground_truth benchmarks/"
echo "    # LAN + boot: re-run ./install.sh --with-dashboard-service --with-dashboard-lan"
echo "    # Org TLS cert: /etc/atlas/dashboard/tls.crt + tls.key (no UI)"
echo ""
echo "  Start a new (production) case:"
echo "    cp -r $ATLAS_DIR/case-template ~/cases/<CASE_ID>"
echo "    # Edit ~/cases/<CASE_ID>/CASE.md with evidence paths"
echo "    cd ~/cases/<CASE_ID>"
echo "    atlas run                       # or: atlas chat"
echo ""
echo "  Local openai-compat backend (optional, e.g. Foundation-Sec-8B via vLLM):"
echo "    vllm serve \"fdtn-ai/Foundation-Sec-8B-Reasoning\" --reasoning-parser minimax_m2"
echo "    then set REASON_BACKEND=openai-compat, REASON_URL=http://localhost:8000 in .env"
echo ""
echo "  Uninstall everything this script added: ./uninstall.sh"
echo ""
echo "  Full walkthrough: docs/try-it-out.md"
echo ""
