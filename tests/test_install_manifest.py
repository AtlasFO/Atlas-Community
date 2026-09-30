"""install.sh's manifest and INDXParse step, run as install.sh runs them.

uninstall.sh removes only what `.install-manifest.json` lists. The file has to
hold what every install run added — a rerun's steps find their tools present
and add nothing — and never a package that predated Atlas, which
`uninstall.sh --purge-system-packages` would otherwise remove. These tests
extract install.sh's own functions and run them in bash under `set -euo
pipefail` against a scratch directory, with shims for the system commands.
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
INSTALL_SH = (REPO / "install.sh").read_text()
VERSIONS_FILE = REPO / "install-versions.env"
STALE = "/usr/local/bin/INDXParse.py"


def _block(pattern: str) -> str:
    m = re.search(pattern, INSTALL_SH, re.S | re.M)
    assert m, f"install.sh no longer matches {pattern!r}"
    return m.group(0)


def _functions(stale: str = STALE) -> str:
    return "\n".join([
        _block(r"^MANIFEST_NEW_PKGS=\(\).*?^MANIFEST_WRITTEN=0$"),
        _block(r"^record_pkgs\(\) \{.*?$"),
        _block(r"^record_path\(\) \{.*?$"),
        _block(r"^forget_path\(\) \{\n.*?^\}$"),
        _block(r"^pkg_installed\(\) \{\n.*?^\}$"),
        _block(r"^apt_install_new\(\) \{\n.*?^\}$"),
        # The heredoc holds a `}` at column 0 too: end at the brace after it.
        _block(r"^write_manifest\(\) \{\n.*?^PYEOF\n.*?^\}$"),
        _block(r"^_manifest_on_exit\(\) \{\n.*?^\}$"),
        _block(r"^install_indxparse\(\) \{\n.*?^\}$"),
        _block(r"^remove_unrunnable_indxparse\(\) \{\n.*?^\}$").replace(STALE, stale),
    ])


def _run(atlas_dir: Path, body: str, env: dict | None = None, stale: str = STALE):
    script = "\n".join([
        "set -euo pipefail",
        # install.sh run as root exports a `sudo` function, which this suite
        # inherits in its smoke step; it would outrank the PATH shims.
        "unset -f sudo",
        'ok() { echo "OK: $*"; }',
        'warn() { echo "WARN: $*"; }',
        'info() { echo "INFO: $*"; }',
        f'ATLAS_DIR="{atlas_dir}"',
        f'VENV_DIR="{atlas_dir}/.venv"',
        f'source "{VERSIONS_FILE}"',
        _functions(stale),
        body,
    ])
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          env=env, timeout=60)


def _manifest(atlas_dir: Path) -> dict:
    return json.loads((atlas_dir / ".install-manifest.json").read_text())


def _seed(atlas_dir: Path, **fields) -> None:
    base = {"installed_at": "2026-01-01T00:00:00+0000", "atlas_dir": str(atlas_dir),
            "venv_dir": str(atlas_dir / ".venv"), "new_apt_packages": [],
            "installed_paths": [], "gift_ppa_added": False, "zeek_repo_added": False,
            "smb_share_enabled": False, "dashboard_service_enabled": False,
            "dotnet_ppa_added": False, "sudoers_file": ""}
    base.update(fields)
    (atlas_dir / ".install-manifest.json").write_text(json.dumps(base))


def _shims(tmp_path: Path, **scripts: str) -> dict:
    """A PATH whose first directory holds the given commands."""
    shims = tmp_path / "shims"
    shims.mkdir(exist_ok=True)
    for name, text in scripts.items():
        path = shims / name.replace("_", "-")
        path.write_text(text)
        path.chmod(0o755)
    return {**os.environ, "PATH": f"{shims}:{os.environ['PATH']}"}


# ── merge ────────────────────────────────────────────────────────────────────

def test_a_rerun_merges_into_what_earlier_runs_recorded(tmp_path):
    _seed(tmp_path, new_apt_packages=["sleuthkit", "plaso-tools"],
          installed_paths=[{"type": "dir", "path": "/opt/regripper"},
                           {"type": "file", "path": "/usr/local/bin/chainsaw"}],
          gift_ppa_added=True, sudoers_file="/etc/sudoers.d/atlas-jane")
    res = _run(tmp_path, "\n".join([
        "record_pkgs samba",
        "record_path dir /opt/onedrive-odl",
        "record_path dir /opt/regripper",
        "MANIFEST_FLAG_DOTNET_PPA=1",
        "write_manifest",
    ]))
    assert res.returncode == 0, res.stderr
    m = _manifest(tmp_path)
    assert m["new_apt_packages"] == ["plaso-tools", "samba", "sleuthkit"]
    assert [p["path"] for p in m["installed_paths"]] == [
        "/opt/regripper", "/usr/local/bin/chainsaw", "/opt/onedrive-odl"], \
        "earlier paths first, each once"
    assert m["gift_ppa_added"] is True, "a flag an earlier run set stays set"
    assert m["dotnet_ppa_added"] is True
    assert m["zeek_repo_added"] is False
    assert m["sudoers_file"] == "/etc/sudoers.d/atlas-jane"
    assert m["installed_at"] == "2026-01-01T00:00:00+0000", "the first install's time"
    assert m["updated_at"] != m["installed_at"]


def test_a_first_run_writes_what_it_recorded(tmp_path):
    res = _run(tmp_path, "record_pkgs ssdeep\n"
                         "MANIFEST_SUDOERS_FILE=/etc/sudoers.d/atlas-jane\nwrite_manifest")
    assert res.returncode == 0, res.stderr
    assert "OK: Install manifest written" in res.stdout
    m = _manifest(tmp_path)
    assert m["new_apt_packages"] == ["ssdeep"]
    assert m["installed_paths"] == []
    assert m["sudoers_file"] == "/etc/sudoers.d/atlas-jane"
    assert m["venv_dir"] == str(tmp_path / ".venv")


def test_merging_the_same_records_again_changes_nothing_but_the_time(tmp_path):
    body = "record_pkgs hashdeep\nrecord_path dir /opt/didierstevens\nwrite_manifest"
    assert _run(tmp_path, body).returncode == 0
    first = _manifest(tmp_path)
    assert _run(tmp_path, body).returncode == 0
    second = _manifest(tmp_path)
    first.pop("updated_at"), second.pop("updated_at")
    assert first == second


def test_the_manifest_stays_readable_for_other_users(tmp_path):
    res = _run(tmp_path, "umask 022\nrecord_pkgs foremost\nwrite_manifest")
    assert res.returncode == 0, res.stderr
    mode = stat.S_IMODE((tmp_path / ".install-manifest.json").stat().st_mode)
    assert mode == 0o644, oct(mode)
    assert not list(tmp_path.glob("*.tmp")), "no temporary file is left behind"


def test_a_path_the_run_removed_leaves_the_manifest(tmp_path):
    _seed(tmp_path, installed_paths=[{"type": "file", "path": STALE},
                                     {"type": "dir", "path": "/opt/regripper"}])
    res = _run(tmp_path, f"forget_path {STALE}\nwrite_manifest")
    assert res.returncode == 0, res.stderr
    assert [p["path"] for p in _manifest(tmp_path)["installed_paths"]] == ["/opt/regripper"]


def test_a_path_removed_and_installed_again_in_one_run_stays(tmp_path):
    _seed(tmp_path, installed_paths=[{"type": "file", "path": "/usr/local/bin/jpseek"}])
    res = _run(tmp_path, "forget_path /usr/local/bin/jpseek\n"
                         "record_path file /usr/local/bin/jpseek\nwrite_manifest")
    assert res.returncode == 0, res.stderr
    assert _manifest(tmp_path)["installed_paths"] == [
        {"type": "file", "path": "/usr/local/bin/jpseek"}]


def test_a_path_installed_and_removed_in_one_run_is_not_recorded(tmp_path):
    res = _run(tmp_path, "record_path file /usr/local/bin/jphide\n"
                         "record_path dir /opt/didierstevens\n"
                         "forget_path /usr/local/bin/jphide\nwrite_manifest")
    assert res.returncode == 0, res.stderr
    assert [p["path"] for p in _manifest(tmp_path)["installed_paths"]] == ["/opt/didierstevens"]


def test_an_unreadable_previous_manifest_is_kept_beside_the_new_one(tmp_path):
    (tmp_path / ".install-manifest.json").write_text("{not json")
    res = _run(tmp_path, "record_pkgs hashdeep\nwrite_manifest")
    assert res.returncode == 0, res.stderr
    assert "WARN:" in res.stdout, "the operator is told"
    kept = list(tmp_path.glob(".install-manifest.json.unreadable-*"))
    assert len(kept) == 1 and kept[0].read_text() == "{not json"
    assert _manifest(tmp_path)["new_apt_packages"] == ["hashdeep"]


def test_a_previous_manifest_with_wrong_types_counts_as_unreadable(tmp_path):
    _seed(tmp_path, new_apt_packages="sleuthkit")  # a string where a list belongs
    res = _run(tmp_path, "record_pkgs hashdeep\nwrite_manifest")
    assert res.returncode == 0, res.stderr
    assert "WARN:" in res.stdout
    assert _manifest(tmp_path)["new_apt_packages"] == ["hashdeep"], \
        "not the letters of the string merged in"
    assert len(list(tmp_path.glob(".install-manifest.json.unreadable-*"))) == 1


def test_an_earlier_unreadable_copy_is_never_overwritten(tmp_path):
    manifest = tmp_path / ".install-manifest.json"
    manifest.write_text("first")
    res = _run(tmp_path, f"write_manifest\necho second > '{manifest}'\nwrite_manifest")
    assert res.returncode == 0, res.stderr
    kept = sorted(p.read_text().strip() for p in tmp_path.glob(".install-manifest.json.unreadable-*"))
    assert kept == ["first", "second"]


# ── write failures ───────────────────────────────────────────────────────────

def test_a_write_that_fails_warns_and_returns_non_zero(tmp_path):
    env = _shims(tmp_path, python3="#!/bin/sh\nexit 1\n")
    res = _run(tmp_path, 'if write_manifest; then echo "rc=0"; else echo "rc=$?"; fi', env=env)
    assert res.returncode == 0, res.stderr
    assert "WARN: Could not write" in res.stdout
    assert "OK:" not in res.stdout, "no success line for a write that did not happen"
    assert "rc=1" in res.stdout


def test_a_write_into_an_unwritable_directory_warns_and_returns_non_zero(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root writes anywhere")
    target = tmp_path / "atlas"
    target.mkdir()
    target.chmod(0o555)
    try:
        res = _run(target, 'if write_manifest; then echo "rc=0"; else echo "rc=$?"; fi')
    finally:
        target.chmod(0o755)
    assert "WARN: Could not write" in res.stdout and "rc=1" in res.stdout
    assert "OK:" not in res.stdout


# ── exit hook ────────────────────────────────────────────────────────────────

def test_a_run_that_stops_midway_still_records_what_it_installed(tmp_path):
    res = _run(tmp_path, "trap _manifest_on_exit EXIT\nrecord_pkgs foremost\nfalse\necho unreachable")
    assert res.returncode == 1, "the script's own exit status is kept"
    assert "unreachable" not in res.stdout
    assert _manifest(tmp_path)["new_apt_packages"] == ["foremost"]


@pytest.mark.parametrize("ending,status", [(":", 0), ("false", 1), ("exit 7", 7)])
@pytest.mark.parametrize("failure", ["python3 fails", "python3 absent", "directory unwritable"])
def test_a_failing_write_at_exit_leaves_the_exit_status_alone(tmp_path, ending, status, failure):
    atlas_dir, env, body = tmp_path, None, "trap _manifest_on_exit EXIT\nrecord_pkgs scalpel\n"
    if failure == "python3 fails":
        env = _shims(tmp_path, python3="#!/bin/sh\nexit 1\n")
    elif failure == "python3 absent":
        body += 'PATH="/nonexistent"\n'
    else:
        if os.geteuid() == 0:
            pytest.skip("root writes anywhere")
        atlas_dir = tmp_path / "atlas"
        atlas_dir.mkdir()
        atlas_dir.chmod(0o555)
    try:
        res = _run(atlas_dir, body + ending, env=env)
    finally:
        if atlas_dir != tmp_path:
            atlas_dir.chmod(0o755)
    assert res.returncode == status, (res.stdout, res.stderr)
    assert "OK:" not in res.stdout
    if failure == "python3 absent":
        assert "WARN" not in res.stdout, "without python3 the hook does not try to write"


def test_the_exit_hook_does_not_write_again_after_step_seven(tmp_path):
    res = _run(tmp_path, "\n".join([
        "trap _manifest_on_exit EXIT",
        "record_pkgs scalpel",
        "MANIFEST_WRITTEN=1",
        "write_manifest || true",
        "record_pkgs recorded-after-the-write",
    ]))
    assert res.returncode == 0, res.stderr
    assert _manifest(tmp_path)["new_apt_packages"] == ["scalpel"]


def test_the_exit_hook_is_set_before_anything_is_installed():
    trap = INSTALL_SH.index("\ntrap _manifest_on_exit EXIT\n")
    assert trap > INSTALL_SH.index("\nwrite_manifest() {")
    assert trap < INSTALL_SH.index('step "Checking prerequisites"')
    assert _block(r'^step "Recording install manifest"\nMANIFEST_WRITTEN=1\nwrite_manifest \|\| true$')


@pytest.mark.parametrize("args,status", [(["-h"], 0), (["--no-such-option"], 1)])
def test_help_and_an_unknown_option_write_no_manifest(tmp_path, args, status):
    shutil.copy(REPO / "install.sh", tmp_path / "install.sh")
    shutil.copy(VERSIONS_FILE, tmp_path / "install-versions.env")
    res = subprocess.run(["bash", str(tmp_path / "install.sh"), *args],
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == status, res.stdout + res.stderr
    assert not list(tmp_path.glob(".install-manifest.json*"))


# ── apt_install_new ──────────────────────────────────────────────────────────

DPKG_QUERY = """#!/bin/sh
for last; do :; done
case " $RC_PKGS " in *" $last "*) printf 'rc '; exit 0 ;; esac
case " $MULTI " in *" $last "*) printf 'ii ii '; exit 0 ;; esac
case " $PRESENT " in *" $last "*) printf 'ii '; exit 0 ;; esac
exit 1
"""


def _apt_env(tmp_path: Path, present: str = "", rc_pkgs: str = "", multi: str = "",
             apt_rc: int = 0) -> dict:
    env = _shims(tmp_path, dpkg_query=DPKG_QUERY, sudo='#!/bin/sh\nexec "$@"\n',
                 apt_get=f'#!/bin/sh\necho "$@" >> "$APT_LOG"\nexit {apt_rc}\n')
    return {**env, "PRESENT": present, "RC_PKGS": rc_pkgs, "MULTI": multi,
            "APT_LOG": str(tmp_path / "apt.log")}


def test_apt_install_new_installs_and_records_only_the_missing_packages(tmp_path):
    res = _run(tmp_path, 'apt_install_new libewf-tools libbde-tools libvshadow-tools\n'
                         'printf "rec:%s\\n" "${MANIFEST_NEW_PKGS[@]}"',
               env=_apt_env(tmp_path, present="libbde-tools"))
    assert res.returncode == 0, res.stderr
    assert (tmp_path / "apt.log").read_text().split() == [
        "install", "-y", "libewf-tools", "libvshadow-tools"]
    assert res.stdout.split() == ["rec:libewf-tools", "rec:libvshadow-tools"], \
        "a package that was already installed is never recorded"


def test_apt_install_new_does_nothing_when_everything_is_present(tmp_path):
    res = _run(tmp_path, 'apt_install_new xmount\necho "count=${#MANIFEST_NEW_PKGS[@]}"',
               env=_apt_env(tmp_path, present="xmount"))
    assert res.returncode == 0, res.stderr
    assert not (tmp_path / "apt.log").exists()
    assert "count=0" in res.stdout


def test_apt_install_new_records_nothing_when_apt_fails(tmp_path):
    res = _run(tmp_path, 'if apt_install_new ewf-tools; then echo installed; else echo failed; fi\n'
                         'echo "count=${#MANIFEST_NEW_PKGS[@]}"',
               env=_apt_env(tmp_path, apt_rc=100))
    assert res.returncode == 0, res.stderr
    assert "failed" in res.stdout and "count=0" in res.stdout


def test_a_package_removed_with_its_conffiles_counts_as_missing(tmp_path):
    res = _run(tmp_path, 'apt_install_new libesedb-tools\nprintf "rec:%s\\n" "${MANIFEST_NEW_PKGS[@]}"',
               env=_apt_env(tmp_path, rc_pkgs="libesedb-tools"))
    assert res.returncode == 0, res.stderr
    assert res.stdout.split() == ["rec:libesedb-tools"]


def test_a_package_installed_for_two_architectures_counts_as_installed(tmp_path):
    res = _run(tmp_path, 'apt_install_new libc6\necho "count=${#MANIFEST_NEW_PKGS[@]}"',
               env=_apt_env(tmp_path, multi="libc6"))
    assert res.returncode == 0, res.stderr
    assert "count=0" in res.stdout and not (tmp_path / "apt.log").exists()


def test_steps_that_may_meet_preinstalled_packages_record_only_what_they_add():
    """These steps install without a presence check of their own; recording
    what they name would claim a SIFT host's or the GIFT PPA's packages."""
    assert not re.search(r'record_pkgs (libewf-tools|ewf-tools|xmount|"\$\{LIBYAL_PKGS'
                         r'|"python\$\{PYV\}-venv"|python3-venv|packages-microsoft-prod dotnet)',
                         INSTALL_SH)
    for call in ("apt_install_new libewf-tools libbde-tools libvshadow-tools",
                 "apt_install_new ewf-tools libbde-utils libvshadow-utils xmount",
                 'apt_install_new "${LIBYAL_PKGS[@]}"',
                 'apt_install_new "python${PYV}-venv" python3-pip',
                 '[ "$MS_PROD_PRESENT" = 1 ] || record_pkgs packages-microsoft-prod',
                 '[ "$DOTNET_PKG_PRESENT" = 1 ] || record_pkgs dotnet-runtime-9.0'):
        assert call in INSTALL_SH, call


# ── INDXParse ────────────────────────────────────────────────────────────────

def _pin() -> str:
    m = re.search(r"^INDXPARSE_REF=([0-9a-f]{40})$", VERSIONS_FILE.read_text(), re.M)
    assert m, "install-versions.env pins INDXParse to a full commit"
    return m.group(1)


PIP = """#!/bin/sh
echo "$*" >> "$PIP_LOG"
case "$*" in *--force-reinstall*) rc=${PIP_RC1:-0} ;; *) rc=${PIP_RC2:-0} ;; esac
if [ "$rc" = 0 ] && [ ! -e "$(dirname "$0")/INDXParse.py" ]; then
    printf '#!/bin/sh\\nexit 0\\n' > "$(dirname "$0")/INDXParse.py"
    chmod +x "$(dirname "$0")/INDXParse.py"
fi
exit $rc
"""


def _venv(tmp_path: Path, installed_commit: str, script: str | None = "#!/bin/sh\nexit 0\n") -> dict:
    """A venv whose python reports `installed_commit` and whose pip logs its calls."""
    bin_dir = tmp_path / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    for name, text in (("python", '#!/bin/sh\necho "$AT"\n'), ("pip", PIP)):
        (bin_dir / name).write_text(text)
        (bin_dir / name).chmod(0o755)
    if script is not None:
        (bin_dir / "INDXParse.py").write_text(script)
        (bin_dir / "INDXParse.py").chmod(0o755)
    return {**os.environ, "AT": installed_commit, "PIP_LOG": str(tmp_path / "pip.log")}


def _pip_calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "pip.log"
    return log.read_text().splitlines() if log.exists() else []


RUN_STEP = 'if install_indxparse; then echo "step=0"; else echo "step=1"; fi'
OTHER_COMMIT = "1" * 40  # synthetic: any commit that is not the pin


def test_indxparse_at_another_commit_is_forced_to_the_pin(tmp_path):
    env = _venv(tmp_path, installed_commit=OTHER_COMMIT)
    res = _run(tmp_path, RUN_STEP, env=env)
    assert "step=0" in res.stdout, res.stdout
    spec = f"indxparse @ git+https://github.com/williballenthin/INDXParse@{_pin()}"
    assert _pip_calls(tmp_path) == [f"install --force-reinstall --no-deps {spec}",
                                    f"install {spec}"]


def test_indxparse_at_the_pin_without_its_script_is_installed_again(tmp_path):
    env = _venv(tmp_path, installed_commit=_pin(), script=None)
    res = _run(tmp_path, RUN_STEP, env=env)
    assert "step=0" in res.stdout, res.stdout
    assert [c.split(" indxparse")[0] for c in _pip_calls(tmp_path)] == [
        "install --force-reinstall --no-deps", "install"]


def test_a_failed_dependency_install_keeps_the_tool(tmp_path):
    env = {**_venv(tmp_path, installed_commit=OTHER_COMMIT), "PIP_RC2": "1"}
    res = _run(tmp_path, RUN_STEP, env=env)
    assert "step=0" in res.stdout, "INDXParse.py itself does not need jinja2"
    assert "WARN:" in res.stdout and "dependencies" in res.stdout
    assert len(_pip_calls(tmp_path)) == 2


def _dist(site: Path, commit: str) -> None:
    """What pip leaves for a VCS install: a dist-info with direct_url.json."""
    info = site / "indxparse-1.1.9.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text("Metadata-Version: 2.1\nName: indxparse\nVersion: 1.1.9\n")
    (info / "direct_url.json").write_text(json.dumps({
        "url": "https://github.com/williballenthin/INDXParse",
        "vcs_info": {"vcs": "git", "commit_id": commit, "requested_revision": commit}}))


def test_the_pin_check_reads_the_commit_pip_recorded(tmp_path):
    """The step's own python one-liner, run for real against a dist-info."""
    env = _venv(tmp_path, installed_commit="")
    (tmp_path / ".venv" / "bin" / "python").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    site = tmp_path / "site"
    env = {**env, "PYTHONPATH": str(site)}
    _dist(site, _pin())
    res = _run(tmp_path, RUN_STEP, env=env)
    assert "already installed" in res.stdout and _pip_calls(tmp_path) == [], res.stdout
    shutil.rmtree(site)
    _dist(site, OTHER_COMMIT)
    res = _run(tmp_path, RUN_STEP, env=env)
    assert _pip_calls(tmp_path)[0].startswith("install --force-reinstall --no-deps"), res.stdout


def test_indxparse_at_the_pin_runs_pip_not_at_all(tmp_path):
    env = _venv(tmp_path, installed_commit=_pin())
    res = _run(tmp_path, RUN_STEP, env=env)
    assert "step=0" in res.stdout and "already installed" in res.stdout
    assert _pip_calls(tmp_path) == []


def test_a_failed_indxparse_fetch_stops_before_the_second_call(tmp_path):
    env = {**_venv(tmp_path, installed_commit="", script=None), "PIP_RC1": "1"}
    res = _run(tmp_path, RUN_STEP, env=env)
    assert "step=1" in res.stdout
    assert "WARN: Could not install INDXParse" in res.stdout and "reports it missing" in res.stdout
    assert len(_pip_calls(tmp_path)) == 1


def test_an_indxparse_that_does_not_start_fails_the_step(tmp_path):
    env = _venv(tmp_path, installed_commit=_pin(), script="#!/bin/sh\nexit 3\n")
    res = _run(tmp_path, RUN_STEP, env=env)
    assert "step=1" in res.stdout and "does not start" in res.stdout


def test_the_unrunnable_copy_goes_only_after_the_venv_copy_started():
    assert _block(r"^if install_indxparse; then\n    remove_unrunnable_indxparse\nfi$")
    spec = INSTALL_SH.index('git+https://github.com/williballenthin/INDXParse@${INDXPARSE_REF}')
    step = INSTALL_SH.index("\nif install_indxparse; then\n")
    requirements = INSTALL_SH.index('"$VENV_DIR/bin/pip" install -r "$ATLAS_DIR/requirements.txt"')
    assert requirements < step and spec < step, "installed into the venv once it exists"
    assert not re.search(r'install -m 0755 "\$INDX_SRC"', INSTALL_SH), \
        "the package module is no command: it is not copied to /usr/local/bin"


def test_a_module_copied_as_indxparse_is_removed_and_forgotten(tmp_path):
    target = tmp_path / "INDXParse.py"
    target.write_text("#    This file is part of a package.\nimport argparse\n")
    target.chmod(0o755)
    res = _run(tmp_path, 'remove_unrunnable_indxparse\nprintf "forgot:%s\\n" "${MANIFEST_FORGET_PATHS[@]}"',
               env=_shims(tmp_path, sudo='#!/bin/sh\nexec "$@"\n'), stale=str(target))
    assert res.returncode == 0, res.stderr
    assert not target.exists()
    assert f"forgot:{target}" in res.stdout.split()
    assert "INFO: Removed" in res.stdout


def test_a_working_indxparse_with_an_interpreter_line_stays(tmp_path):
    target = tmp_path / "INDXParse.py"
    target.write_text("#!/usr/bin/env python3\nprint('ok')\n")
    target.chmod(0o755)
    res = _run(tmp_path, 'remove_unrunnable_indxparse\necho "forgotten=${#MANIFEST_FORGET_PATHS[@]}"',
               env=_shims(tmp_path, sudo='#!/bin/sh\nexec "$@"\n'), stale=str(target))
    assert res.returncode == 0, res.stderr
    assert target.exists() and "forgotten=0" in res.stdout


def test_a_copy_that_cannot_be_removed_is_reported_and_stays_recorded(tmp_path):
    target = tmp_path / "INDXParse.py"
    target.write_text("# a package module\n")
    res = _run(tmp_path, 'remove_unrunnable_indxparse\necho "forgotten=${#MANIFEST_FORGET_PATHS[@]}"',
               env=_shims(tmp_path, sudo="#!/bin/sh\nexit 1\n"), stale=str(target))
    assert res.returncode == 0, res.stderr
    assert target.exists() and "forgotten=0" in res.stdout
    assert "WARN: Could not remove" in res.stdout


def test_no_copy_in_usr_local_bin_is_nothing_to_do(tmp_path):
    res = _run(tmp_path, 'remove_unrunnable_indxparse\necho "forgotten=${#MANIFEST_FORGET_PATHS[@]}"',
               stale=str(tmp_path / "absent" / "INDXParse.py"))
    assert res.returncode == 0, res.stderr
    assert res.stdout.split() == ["forgotten=0"]


def test_the_dotnet_step_looks_before_it_installs():
    """The snapshot of what was installed has to precede the attempts,
    or the step would record the packages it had just installed as present."""
    snapshot = INSTALL_SH.index("DOTNET_PKG_PRESENT=0; pkg_installed dotnet-runtime-9.0")
    assert INSTALL_SH.index("MS_PROD_PRESENT=0; pkg_installed packages-microsoft-prod") > snapshot
    assert INSTALL_SH.index("\npkg_installed() {") < snapshot
    for attempt in ("if _install_dotnet9_ubuntu24 &>", "if _install_dotnet9_msrepo &>"):
        assert INSTALL_SH.index(attempt) > snapshot, attempt
