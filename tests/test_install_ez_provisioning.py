"""Drift guards for install.sh's EZ Tools provisioning step (§1cy).

tools/eztools.py runs `dotnet <EZ_DIR>/<Tool>.dll`, but nothing installed those
dlls until install.sh grew a provisioning step — on a bare (non-SIFT) host the
whole ez.* family was silently unavailable. These tests keep the two sides in
sync: if someone adds an ez_* tool that invokes a new dll, install.sh must learn
to download it, and the permission normalization must stay in place (without it,
non-owner analysts on a shared VM hit PermissionError on the dlls).
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO / "install.sh"
EZTOOLS_PY = REPO / "tools" / "eztools.py"


def _install_sh() -> str:
    return INSTALL_SH.read_text()


def _dlls_invoked_by_eztools() -> set[str]:
    """Every `{EZ}/…/Foo.dll` path tools/eztools.py hands to run_dotnet."""
    return set(re.findall(r'\{EZ\}/([\w./]+\.dll)', EZTOOLS_PY.read_text()))


def _provisioned_dlls() -> set[str]:
    """Sentinel paths install.sh checks/installs, derived from EZ_TOOLS + ez_dll()."""
    body = _install_sh()
    block = re.search(r'^EZ_TOOLS=\((.*?)\)$', body, re.S | re.M)
    assert block, "install.sh no longer defines an EZ_TOOLS array"
    tools = block.group(1).split()

    # Subdirectory tools carry their own folder inside the zip; ez_dll() maps them.
    overrides = dict(re.findall(r'^\s+(\w+)\)\s+echo "([\w./]+\.dll)" ;;', body, re.M))
    return {overrides.get(t, f"{t}.dll") for t in tools}


def test_every_ez_tool_is_provisioned():
    missing = _dlls_invoked_by_eztools() - _provisioned_dlls()
    assert not missing, (
        f"tools/eztools.py invokes {sorted(missing)} but install.sh does not "
        "provision them — add the tool to EZ_TOOLS (and ez_dll() if the archive "
        "ships its own subdirectory)."
    )


def test_no_provisioned_tool_is_unused():
    """Catches typos in EZ_TOOLS: a name no ez_* tool ever runs."""
    unused = _provisioned_dlls() - _dlls_invoked_by_eztools()
    assert not unused, (
        f"install.sh downloads {sorted(unused)} but no ez_* tool invokes it — "
        "typo in EZ_TOOLS/ez_dll(), or a stale entry."
    )


def test_subdir_tools_extract_into_the_base_dir():
    """EvtxeCmd/RECmd/SQLECmd nest their own folder inside the zip. Extracting
    into a pre-created subdir yields …/EvtxeCmd/EvtxeCmd/EvtxECmd.dll."""
    body = _install_sh()
    unzip = re.search(r'unzip .*-d "\$EZ_DIR"', body)
    assert unzip, "install.sh must extract EZ archives into $EZ_DIR itself"
    assert not re.search(r'mkdir -p "\$EZ_DIR/', body), (
        "install.sh must not pre-create per-tool subdirectories under $EZ_DIR"
    )


def test_permissions_are_normalized_for_non_owner_analysts():
    """unzip derives modes from the extracting shell's umask (the archives store
    FAT attributes), so subdirs can land at 774 — no traverse bit for 'other'."""
    assert re.search(r'chmod -R a\+rX "\$EZ_DIR"', _install_sh()), (
        "install.sh must run `chmod -R a+rX \"$EZ_DIR\"` after extracting, or "
        "every non-owner analyst on a shared VM gets PermissionError on the dlls"
    )


def test_ez_download_url_targets_net9():
    """The net6 zips 404 — EZ Tools ship framework-dependent net9 builds."""
    body = _install_sh()
    assert "download.mikestammer.com/net9" in body
    assert "/net6" not in body


def test_dotnet_probe_does_not_require_the_sdk():
    """`dotnet --version` reports the SDK version and exits 145 on a
    runtime-only host, which would falsely demand dotnet-sdk-9.0."""
    body = _install_sh()
    assert "dotnet --list-runtimes" in body
    assert not re.search(r'^dotnet --version .*\|\| fail', body, re.M), (
        "install.sh must not hard-fail on `dotnet --version` — probe "
        "--list-runtimes for Microsoft.NETCore.App 9.x instead"
    )


def test_chainsaw_share_dir_created_outside_the_sigma_guard():
    """An archive with mappings/ but no sigma/ must not abort the install:
    the second `cp -r` needs the parent dir to exist unconditionally."""
    body = _install_sh()
    mkdir = body.index("sudo mkdir -p /usr/local/share/chainsaw")
    sigma_guard = body.index('if [ -d "$CHAINSAW_TMP/chainsaw/sigma" ]; then')
    assert mkdir < sigma_guard, (
        "the chainsaw share dir must be created before the sigma/ guard, not "
        "inside it"
    )
