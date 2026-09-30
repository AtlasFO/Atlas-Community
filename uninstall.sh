#!/usr/bin/env bash
# Atlas uninstaller — removes exactly what install.sh added, and nothing else.
#
# Reads .install-manifest.json (written by install.sh) so this never guesses:
# apt packages that predated Atlas are never touched, and case evidence under
# ~/cases is never touched under any flag — this is a forensics tool, and
# silently deleting evidence is not a risk worth taking for convenience.
set -euo pipefail

ATLAS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ATLAS_DIR/.venv"
MANIFEST="$ATLAS_DIR/.install-manifest.json"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
warn() { echo -e "${YELLOW}  !${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*"; exit 1; }
step() { echo -e "\n${GREEN}▶${NC} $*"; }

ASSUME_YES=0
DRY_RUN=0
PURGE_SYSTEM_PACKAGES=0

usage() {
    cat <<EOF
Atlas uninstaller

Usage: ./uninstall.sh [options]

  -y, --yes                   Non-interactive: skip the confirmation prompt.
  --dry-run                   Print what would be removed, remove nothing.
  --purge-system-packages     Also 'apt-get purge' the apt packages this
                               install newly added, including their conffiles
                               (per the manifest — never removes a package
                               that predated Atlas).
  -h, --help                  This help.

Never touches, under any flag: ~/cases (case evidence), the repo checkout
itself, or .env (API keys). Delete those yourself if you actually want them
gone.
EOF
}

for arg in "$@"; do
    case "$arg" in
        -y|--yes) ASSUME_YES=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --purge-system-packages) PURGE_SYSTEM_PACKAGES=1 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "Unknown option: $arg (see --help)" ;;
    esac
done

echo ""
echo "  Atlas uninstaller"
echo "  ================="
echo "  Repo: $ATLAS_DIR"
[ "$DRY_RUN" = 1 ] && echo -e "  ${YELLOW}(dry run — nothing will actually be removed)${NC}"
echo ""

if [ ! -f "$MANIFEST" ]; then
    fail "No install manifest found at $MANIFEST — either install.sh was never run here, or this predates the manifest feature. Nothing to safely automate; remove $ATLAS_DIR/.venv, /etc/sudoers.d/atlas-\$USER, and anything else you installed manually."
fi

# Root vs sudo — same shadow-function approach as install.sh, so this works
# identically whether run as a regular user or as root in a container.
if [ "$(id -u)" = 0 ]; then
    RUNNING_AS_ROOT=1
    sudo() { "$@"; }
else
    RUNNING_AS_ROOT=0
    command -v sudo >/dev/null 2>&1 || fail "Not running as root and 'sudo' is not installed."
fi

# ── Parse the manifest ────────────────────────────────────────────────────────

MANIFEST_DATA="$(python3 - "$MANIFEST" <<'PYEOF'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
print(data.get("venv_dir", ""))
print("\x1f".join(data.get("new_apt_packages", [])))
for p in data.get("installed_paths", []):
    print(f"{p['type']}:{p['path']}")
print("---FLAGS---")
print("1" if data.get("gift_ppa_added") else "0")
print("1" if data.get("zeek_repo_added") else "0")
print("1" if data.get("smb_share_enabled") else "0")
print("1" if data.get("dashboard_service_enabled") else "0")
print("1" if data.get("dotnet_ppa_added") else "0")
print(data.get("sudoers_file", ""))
PYEOF
)"

MANIFEST_LINES=()
while IFS= read -r line; do MANIFEST_LINES+=("$line"); done <<< "$MANIFEST_DATA"

MANIFEST_VENV="${MANIFEST_LINES[0]:-}"
IFS=$'\x1f' read -r -a MANIFEST_PKGS <<< "${MANIFEST_LINES[1]:-}"
MANIFEST_PATHS=()
i=2
while [ "${MANIFEST_LINES[$i]:-}" != "---FLAGS---" ] && [ $i -lt ${#MANIFEST_LINES[@]} ]; do
    [ -n "${MANIFEST_LINES[$i]}" ] && MANIFEST_PATHS+=("${MANIFEST_LINES[$i]}")
    i=$((i + 1))
done
i=$((i + 1))
MANIFEST_GIFT_PPA="${MANIFEST_LINES[$i]:-0}"; i=$((i + 1))
MANIFEST_ZEEK_REPO="${MANIFEST_LINES[$i]:-0}"; i=$((i + 1))
MANIFEST_SMB_SHARE="${MANIFEST_LINES[$i]:-0}"; i=$((i + 1))
MANIFEST_DASHBOARD_SERVICE="${MANIFEST_LINES[$i]:-0}"; i=$((i + 1))
MANIFEST_DOTNET_PPA="${MANIFEST_LINES[$i]:-0}"; i=$((i + 1))
MANIFEST_SUDOERS="${MANIFEST_LINES[$i]:-}"

# ── Build the removal plan ────────────────────────────────────────────────────

step "Planning removal"

PLAN_DIRS=() PLAN_FILES=() PLAN_SYMLINKS=() PLAN_RADARE2=()

[ -n "$MANIFEST_VENV" ] && [ -d "$MANIFEST_VENV" ] && PLAN_DIRS+=("$MANIFEST_VENV")
if [ -L "$HOME/.venv" ] && [ "$(readlink -f "$HOME/.venv" 2>/dev/null)" = "$(readlink -f "$MANIFEST_VENV" 2>/dev/null)" ]; then
    PLAN_SYMLINKS+=("$HOME/.venv")
fi

for entry in "${MANIFEST_PATHS[@]:-}"; do
    [ -z "$entry" ] && continue
    kind="${entry%%:*}"
    path="${entry#*:}"
    [ -e "$path" ] || [ -L "$path" ] || continue
    case "$kind" in
        dir) PLAN_DIRS+=("$path") ;;
        file) PLAN_FILES+=("$path") ;;
        symlink) PLAN_SYMLINKS+=("$path") ;;
        # radare2's installed binaries are symlinks back into this directory
        # (not copies) — a plain rm -rf leaves dangling symlinks in
        # /usr/local/bin. `make purge` (radare2's own target) removes those
        # too; only fall back to rm -rf if that's unavailable or fails.
        radare2) PLAN_RADARE2+=("$path") ;;
    esac
done

[ -n "$MANIFEST_SUDOERS" ] && [ -f "$MANIFEST_SUDOERS" ] && PLAN_FILES+=("$MANIFEST_SUDOERS")
[ -d "$HOME/.cache/atlas" ] && PLAN_DIRS+=("$HOME/.cache/atlas")
[ -f "$HOME/.atlas_history" ] && PLAN_FILES+=("$HOME/.atlas_history")
[ -f "$MANIFEST" ] && PLAN_FILES+=("$MANIFEST")

echo "  Will remove:"
for d in "${PLAN_DIRS[@]:-}"; do [ -n "$d" ] && echo "    dir:     $d"; done
for f in "${PLAN_FILES[@]:-}"; do [ -n "$f" ] && echo "    file:    $f"; done
for s in "${PLAN_SYMLINKS[@]:-}"; do [ -n "$s" ] && echo "    symlink: $s"; done
for r in "${PLAN_RADARE2[@]:-}"; do [ -n "$r" ] && echo "    radare2 (make purge): $r"; done
if [ "${#MANIFEST_PKGS[@]}" -gt 0 ] && [ -n "${MANIFEST_PKGS[0]:-}" ]; then
    if [ "$PURGE_SYSTEM_PACKAGES" = 1 ]; then
        echo "    apt packages (--purge-system-packages given): ${MANIFEST_PKGS[*]}"
    else
        echo "    apt packages: NOT removed (pass --purge-system-packages to also remove: ${MANIFEST_PKGS[*]})"
    fi
fi
if [ "$MANIFEST_GIFT_PPA" = 1 ]; then
    echo "    ppa:gift/stable: $([ "$PURGE_SYSTEM_PACKAGES" = 1 ] && echo "will be removed" || echo "left in place (--purge-system-packages to remove)")"
fi
if [ "$MANIFEST_ZEEK_REPO" = 1 ]; then
    echo "    security-zeek apt repo: $([ "$PURGE_SYSTEM_PACKAGES" = 1 ] && echo "will be removed" || echo "left in place (--purge-system-packages to remove)")"
fi
if [ "$MANIFEST_SMB_SHARE" = 1 ]; then
    echo "    SMB network share config: $([ "$PURGE_SYSTEM_PACKAGES" = 1 ] && echo "will be removed" || echo "left in place (--purge-system-packages to remove)")"
fi
if [ "$MANIFEST_DASHBOARD_SERVICE" = 1 ]; then
    echo "    systemd unit atlas-dashboard.service: will be disabled and removed"
fi
if [ "$MANIFEST_DOTNET_PPA" = 1 ]; then
    echo "    ppa:dotnet/backports: $([ "$PURGE_SYSTEM_PACKAGES" = 1 ] && echo "will be removed" || echo "left in place (--purge-system-packages to remove)")"
fi
echo ""
echo "  Never touched: ~/cases (case evidence), the repo checkout, .env"
echo ""

if [ "$DRY_RUN" = 1 ]; then
    ok "Dry run — nothing removed"
    exit 0
fi

if [ "$ASSUME_YES" != 1 ]; then
    read -r -p "  Proceed with removal? [y/N] " reply || reply=""
    case "$reply" in
        y|Y|yes|Yes) ;;
        *) echo "  Aborted — nothing removed."; exit 0 ;;
    esac
fi

# ── Execute ────────────────────────────────────────────────────────────────────

if [ "$MANIFEST_DASHBOARD_SERVICE" = 1 ]; then
    step "Stopping the dashboard boot service"
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        sudo systemctl disable --now atlas-dashboard.service 2>/dev/null \
            && ok "Disabled atlas-dashboard.service" \
            || warn "Could not disable atlas-dashboard.service — it may already be stopped"
        sudo systemctl daemon-reload 2>/dev/null || true
    else
        warn "systemd is not PID 1 — not stopping atlas-dashboard.service via systemctl"
    fi
fi

if [ "${#PLAN_RADARE2[@]}" -gt 0 ]; then
    step "Purging radare2"
    for r in "${PLAN_RADARE2[@]:-}"; do
        [ -z "$r" ] && continue
        if [ -f "$r/Makefile" ] && (cd "$r" && sudo make purge) &>/dev/null; then
            ok "Purged radare2 (binaries + $r)"
        else
            warn "make purge failed or unavailable for $r — removing the directory anyway; this leaves dangling symlinks in /usr/local/bin (r2/radare2/rasm2/...) until you clean them up by hand"
            sudo rm -rf "$r"
        fi
    done
fi

step "Removing files and directories"

for d in "${PLAN_DIRS[@]:-}"; do
    [ -z "$d" ] && continue
    if [ -w "$(dirname "$d")" ] || [ "$RUNNING_AS_ROOT" = 1 ]; then
        rm -rf "$d" 2>/dev/null && ok "Removed $d" || { sudo rm -rf "$d" && ok "Removed $d (sudo)"; }
    else
        sudo rm -rf "$d" && ok "Removed $d (sudo)"
    fi
done

for f in "${PLAN_FILES[@]:-}" "${PLAN_SYMLINKS[@]:-}"; do
    [ -z "$f" ] && continue
    if rm -f "$f" 2>/dev/null; then
        ok "Removed $f"
    else
        sudo rm -f "$f" && ok "Removed $f (sudo)"
    fi
done

step "Reverting git hooks path"
if git -C "$ATLAS_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    if [ "$(git -C "$ATLAS_DIR" config --get core.hooksPath 2>/dev/null)" = ".githooks" ]; then
        git -C "$ATLAS_DIR" config --unset core.hooksPath
        ok "Reverted core.hooksPath"
    fi
fi

if [ "$PURGE_SYSTEM_PACKAGES" = 1 ]; then
    if [ "$MANIFEST_SMB_SHARE" = 1 ]; then
        step "Removing the SMB network share config"
        # Un-configure before the package purge below removes samba itself —
        # this runs as a plain `sudo` (not `sudo -n`), so it still works even
        # though the ATLAS_SMB_SHARE sudoers grant was already deleted with
        # the rest of PLAN_FILES above; it may prompt for a password, same as
        # the apt-get purge calls in this block already do.
        if [ -x "$ATLAS_DIR/bin/atlas-smb-share" ]; then
            sudo "$ATLAS_DIR/bin/atlas-smb-share" disable \
                && ok "Removed the SMB share config" \
                || warn "Could not remove the SMB share config — check /etc/samba/atlas-share.conf by hand"
        else
            warn "bin/atlas-smb-share missing — cannot clean up the SMB share config automatically. Remove /etc/samba/atlas-share.conf and its 'include=' line in /etc/samba/smb.conf by hand."
        fi
    fi

    step "Removing apt packages installed by Atlas"
    if [ "${#MANIFEST_PKGS[@]}" -gt 0 ] && [ -n "${MANIFEST_PKGS[0]:-}" ]; then
        # apt-get purge, not remove: --purge-system-packages promises purge,
        # and remove alone leaves conffiles behind — e.g. packages-microsoft-prod
        # registers /etc/apt/sources.list.d/microsoft-prod.list and
        # /etc/apt/trusted.gpg.d/microsoft.gpg as conffiles, so `remove` would
        # leave the Microsoft apt repo and its signing key trusted forever.
        if sudo apt-get purge -y "${MANIFEST_PKGS[@]}" 2>/dev/null; then
            ok "Removed: ${MANIFEST_PKGS[*]}"
        else
            warn "Some packages failed to remove — they may be depended on by other installed software"
        fi
        sudo apt-get autoremove -y >/dev/null 2>&1 || true
    else
        ok "No apt packages were newly installed by Atlas — nothing to remove"
    fi
    if [ "$MANIFEST_GIFT_PPA" = 1 ] && command -v add-apt-repository >/dev/null 2>&1; then
        sudo add-apt-repository -y --remove ppa:gift/stable 2>/dev/null \
            && ok "Removed ppa:gift/stable" \
            || warn "Could not remove ppa:gift/stable automatically"
    fi
    if [ "$MANIFEST_ZEEK_REPO" = 1 ]; then
        sudo rm -f /etc/apt/sources.list.d/security-zeek.list /etc/apt/trusted.gpg.d/security-zeek.gpg \
            && ok "Removed security-zeek apt repo" \
            || warn "Could not remove the security-zeek apt repo files"
    fi
    if [ "$MANIFEST_DOTNET_PPA" = 1 ] && command -v add-apt-repository >/dev/null 2>&1; then
        sudo add-apt-repository -y --remove ppa:dotnet/backports 2>/dev/null \
            && ok "Removed ppa:dotnet/backports" \
            || warn "Could not remove ppa:dotnet/backports automatically"
    fi
fi

echo ""
echo -e "${GREEN}  Atlas uninstalled.${NC}"
echo ""
echo "  Preserved (delete yourself if you want them gone too):"
echo "    - $HOME/cases  (case evidence)"
echo "    - $ATLAS_DIR   (the repo checkout)"
[ -f "$ATLAS_DIR/.env" ] && echo "    - $ATLAS_DIR/.env  (API keys)"
echo ""
