"""Bind address, TLS material, and Host-header allowlist for LAN listen.

These tests describe dashboard.listen before serve.py grows a hardcoded
0.0.0.0 path. Production change that would fail each test is named in
the docstring.
"""
from __future__ import annotations

import http.client
import json
import ssl
import stat
import threading
import time
from pathlib import Path

import pytest

from dashboard import listen


class TestLoopbackBind:
    def test_loopback_literals(self):
        """Fail if 127.0.0.1 / localhost / ::1 stop counting as loopback."""
        for host in ("127.0.0.1", "localhost", "::1"):
            assert listen.is_loopback_bind(host) is True
            assert listen.tls_required(host) is False

    def test_unspecified_and_lan_require_tls(self):
        """Fail if 0.0.0.0 or a LAN IP is treated as loopback (cleartext LAN)."""
        for host in ("0.0.0.0", "192.168.1.10", "::"):
            assert listen.is_loopback_bind(host) is False
            assert listen.tls_required(host) is True


class TestHostHeader:
    def test_strips_port_and_brackets(self):
        """Fail if Host: 192.168.1.5:8765 is not compared as 192.168.1.5."""
        assert listen.normalize_host_header("192.168.1.5:8765") == "192.168.1.5"
        assert listen.normalize_host_header("127.0.0.1") == "127.0.0.1"
        assert listen.normalize_host_header("[::1]:8765") == "::1"
        assert listen.normalize_host_header("LOCALHOST:8765") == "localhost"

    def test_allowlist_accepts_local_names_and_extras(self):
        """Fail if extra reverse-proxy names are ignored or loopback drops out."""
        allow = listen.build_host_allowlist(
            "0.0.0.0", extra="dash.atlas.example, dash.atlas.example:443")
        assert listen.host_header_allowed("127.0.0.1:8765", allow)
        assert listen.host_header_allowed("localhost", allow)
        assert listen.host_header_allowed("dash.atlas.example", allow)

    def test_foreign_host_rejected(self):
        """Fail if Host: evil.com is accepted (DNS rebinding)."""
        allow = listen.build_host_allowlist("127.0.0.1")
        assert listen.host_header_allowed("evil.com", allow) is False
        assert listen.host_header_allowed("evil.com:8765", allow) is False


class TestPublicAddress:
    def test_rfc1918_is_not_public(self):
        assert listen.is_public_ip("10.0.0.1") is False
        assert listen.is_public_ip("192.168.0.5") is False
        assert listen.is_public_ip("172.16.4.1") is False
        assert listen.is_public_ip("127.0.0.1") is False
        assert listen.is_public_ip("::1") is False
        assert listen.is_public_ip("fd00::1") is False

    def test_globally_routable_is_public(self):
        assert listen.is_public_ip("8.8.8.8") is True
        assert listen.is_public_ip("2001:4860:4860::8888") is True


class TestKeyPermissions:
    def test_world_readable_key_refused(self, tmp_path):
        """Fail if a 0644 private key is accepted."""
        key = tmp_path / "key.pem"
        key.write_text("dummy")
        key.chmod(0o644)
        with pytest.raises(listen.TlsError):
            listen.assert_private_key_perms(key)

    def test_owner_only_key_accepted(self, tmp_path):
        key = tmp_path / "key.pem"
        key.write_text("dummy")
        key.chmod(0o600)
        listen.assert_private_key_perms(key)


class TestTlsResolution:
    def test_loopback_returns_none(self, tmp_path):
        """Fail if localhost listen starts requiring a cert."""
        assert listen.resolve_tls_files(bind_host="127.0.0.1") is None

    def test_env_paths_win(self, tmp_path):
        """Fail if ATLAS_DASHBOARD_TLS_* is ignored when both files exist."""
        env_cert = tmp_path / "env.crt"
        env_key = tmp_path / "env.key"
        env_cert.write_text("env-cert")
        env_key.write_text("env-key")
        env_key.chmod(0o600)
        system_dir = tmp_path / "etc"
        system_dir.mkdir()
        (system_dir / "tls.crt").write_text("sys-cert")
        sys_key = system_dir / "tls.key"
        sys_key.write_text("sys-key")
        sys_key.chmod(0o600)
        user_dir = tmp_path / "user"
        got = listen.resolve_tls_files(
            bind_host="0.0.0.0",
            env_cert=str(env_cert),
            env_key=str(env_key),
            system_dir=system_dir,
            user_dir=user_dir,
            generate=False,
        )
        assert got is not None
        cert, key, generated = got
        assert cert == env_cert
        assert key == env_key
        assert generated is False

    def test_system_dropin_beats_user(self, tmp_path):
        """Fail if ~/.config wins over /etc/atlas/dashboard/."""
        system_dir = tmp_path / "etc"
        system_dir.mkdir()
        (system_dir / "tls.crt").write_text("sys-cert")
        sys_key = system_dir / "tls.key"
        sys_key.write_text("sys-key")
        sys_key.chmod(0o600)
        user_dir = tmp_path / "user"
        user_dir.mkdir()
        (user_dir / "cert.pem").write_text("user-cert")
        user_key = user_dir / "key.pem"
        user_key.write_text("user-key")
        user_key.chmod(0o600)
        got = listen.resolve_tls_files(
            bind_host="0.0.0.0",
            system_dir=system_dir,
            user_dir=user_dir,
            generate=False,
        )
        assert got is not None
        cert, key, generated = got
        assert cert == system_dir / "tls.crt"
        assert key == sys_key
        assert generated is False

    def test_user_dropin_used_when_system_absent(self, tmp_path):
        system_dir = tmp_path / "etc"
        user_dir = tmp_path / "user"
        user_dir.mkdir()
        (user_dir / "cert.pem").write_text("user-cert")
        user_key = user_dir / "key.pem"
        user_key.write_text("user-key")
        user_key.chmod(0o600)
        got = listen.resolve_tls_files(
            bind_host="0.0.0.0",
            system_dir=system_dir,
            user_dir=user_dir,
            generate=False,
        )
        assert got is not None
        cert, _key, generated = got
        assert cert == user_dir / "cert.pem"
        assert generated is False

    def test_missing_pair_generates_self_signed(self, tmp_path):
        """Fail if LAN listen with no certs does not mint a user-dir pair."""
        user_dir = tmp_path / "user"
        got = listen.resolve_tls_files(
            bind_host="0.0.0.0",
            system_dir=tmp_path / "missing-etc",
            user_dir=user_dir,
            generate=True,
            san_names=["localhost", "127.0.0.1"],
        )
        assert got is not None
        cert, key, generated = got
        assert generated is True
        assert cert.is_file()
        assert key.is_file()
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
        ctx = listen.make_tls_context(cert, key)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_world_readable_resolved_key_refused(self, tmp_path):
        env_cert = tmp_path / "env.crt"
        env_key = tmp_path / "env.key"
        env_cert.write_text("env-cert")
        env_key.write_text("env-key")
        env_key.chmod(0o644)
        with pytest.raises(listen.TlsError):
            listen.resolve_tls_files(
                bind_host="0.0.0.0",
                env_cert=str(env_cert),
                env_key=str(env_key),
                generate=False,
            )


class TestParseBind:
    def test_default_and_lan(self):
        assert listen.parse_bind_host("127.0.0.1") == "127.0.0.1"
        assert listen.parse_bind_host("0.0.0.0") == "0.0.0.0"
        assert listen.parse_bind_host("localhost") == "localhost"

    def test_rejects_empty_and_junk(self):
        with pytest.raises(ValueError):
            listen.parse_bind_host("")
        with pytest.raises(ValueError):
            listen.parse_bind_host("not a host")

    def test_rejects_ipv6(self):
        # _bind()'s ThreadingTCPServer is AF_INET-only — an IPv6 literal
        # must fail here with a clear message, not at socket-creation with
        # a misleading "no free port" error.
        for host in ("::1", "::", "fd00::1", "2001:db8::1"):
            with pytest.raises(ValueError, match="IPv6"):
                listen.parse_bind_host(host)


class TestFingerprint:
    def test_sha256_of_generated_cert(self, tmp_path):
        cert, key = listen.generate_self_signed(
            tmp_path, names=["localhost", "127.0.0.1"])
        fp = listen.cert_sha256_fingerprint(cert)
        assert len(fp) == 64
        assert fp == listen.cert_sha256_fingerprint(cert)

    def test_generated_dir_not_group_or_world_readable(self, tmp_path):
        import stat
        dest = tmp_path / "tls"
        listen.generate_self_signed(dest, names=["localhost", "127.0.0.1"])
        mode = stat.S_IMODE(dest.stat().st_mode)
        assert mode & 0o077 == 0, f"tls dir mode {mode:04o} leaks to group/world"


def _start(httpd):
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    return thread


class TestServeHostAndTls:
    def test_foreign_host_header_is_400(self, tmp_path, monkeypatch):
        """Fail if Host: evil.com is served instead of rejected."""
        from dashboard import auth
        from dashboard import serve as dash_serve

        monkeypatch.setattr(auth, "DEFAULT_DB_PATH", tmp_path / "auth.db")
        auth.init_db()
        cases = tmp_path / "cases"
        cases.mkdir()
        httpd, port = dash_serve._bind(str(cases), 0)
        _start(httpd)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            conn.request("GET", "/_dashboard/login.html",
                         headers={"Host": "evil.com"})
            resp = conn.getresponse()
            assert resp.status == 400
            resp.read()
        finally:
            httpd.shutdown()

    def test_bootstrap_still_works_on_lan_bind(self, tmp_path, monkeypatch):
        """Fail if first-visit admin signup is blocked on 0.0.0.0."""
        from dashboard import auth
        from dashboard import serve as dash_serve

        monkeypatch.setattr(auth, "DEFAULT_DB_PATH", tmp_path / "auth.db")
        auth.init_db()
        cases = tmp_path / "cases"
        cases.mkdir()
        httpd, port = dash_serve._bind(str(cases), 0, host="0.0.0.0")
        _start(httpd)
        try:
            body = json.dumps({
                "username": "admin",
                "email": "admin@example.com",
                "password": "password123",
            }).encode()
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            conn.request(
                "POST", "/_dashboard/api/bootstrap", body=body,
                headers={"Content-Type": "application/json",
                         "Host": f"127.0.0.1:{port}"},
            )
            resp = conn.getresponse()
            assert resp.status == 200, resp.read()
            assert auth.has_any_users() is True
        finally:
            httpd.shutdown()

    # install.sh runs this after every install (pytest -m install_smoke): the
    # dashboard serves its pages, over the TLS a LAN install uses.
    @pytest.mark.install_smoke
    def test_tls_wrap_serves_https(self, tmp_path, monkeypatch):
        """Fail if the TLS-bound server does not actually speak HTTPS."""
        from dashboard import auth
        from dashboard import serve as dash_serve

        monkeypatch.setattr(auth, "DEFAULT_DB_PATH", tmp_path / "auth.db")
        auth.init_db()
        cases = tmp_path / "cases"
        cases.mkdir()
        cert, key = listen.generate_self_signed(
            tmp_path / "tls", names=["localhost", "127.0.0.1"])
        httpd, port = dash_serve._bind(str(cases), 0, use_tls=True,
                                       tls=(cert, key))
        _start(httpd)
        conn = http.client.HTTPSConnection(
            "127.0.0.1", port, timeout=2, context=ssl._create_unverified_context())
        try:
            conn.request("GET", "/_dashboard/login.html")
            resp = conn.getresponse()
            assert resp.status == 200
            assert b"login" in resp.read().lower()
        finally:
            # An open TLS connection holds the server's graceful shutdown for
            # its full timeout; close it first.
            conn.close()
            httpd.shutdown()

    def test_tls_logout_clears_secure_cookie(self, tmp_path, monkeypatch):
        """Fail if logout omits Secure — browsers will not drop the TLS session cookie."""
        from dashboard import auth
        from dashboard import serve as dash_serve

        monkeypatch.setattr(auth, "DEFAULT_DB_PATH", tmp_path / "auth.db")
        auth.init_db()
        cases = tmp_path / "cases"
        cases.mkdir()
        cert, key = listen.generate_self_signed(
            tmp_path / "tls", names=["localhost", "127.0.0.1"])
        httpd, port = dash_serve._bind(str(cases), 0, use_tls=True,
                                       tls=(cert, key))
        _start(httpd)
        conn = http.client.HTTPSConnection(
            "127.0.0.1", port, timeout=2, context=ssl._create_unverified_context())
        try:
            body = json.dumps({
                "username": "admin",
                "email": "admin@example.com",
                "password": "password123",
            }).encode()
            conn.request(
                "POST", "/_dashboard/api/bootstrap", body=body,
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            assert resp.status == 200, resp.read()
            set_cookie = resp.getheader("Set-Cookie") or ""
            assert "Secure" in set_cookie
            cookie = set_cookie.split(";", 1)[0]
            resp.read()  # finish this body before reusing the keep-alive connection
            conn.request(
                "POST", "/_dashboard/api/logout", body=b"{}",
                headers={"Content-Type": "application/json",
                         "Cookie": cookie},
            )
            resp = conn.getresponse()
            assert resp.status == 200, resp.read()
            clear = resp.getheader("Set-Cookie") or ""
            assert "Secure" in clear
            assert "Max-Age=0" in clear
        finally:
            conn.close()  # see test_tls_wrap_serves_https
            httpd.shutdown()


class TestServiceTemplate:
    def test_unit_template_has_placeholders(self):
        """Fail if the systemd unit loses @USER@ / ExecStart substitutions."""
        text = Path(__file__).resolve().parents[2].joinpath(
            "share/atlas-dashboard.service.in").read_text()
        for token in ("@USER@", "@GROUP@", "@HOME@", "@ATLAS_DIR@", "@VENV_PY@"):
            assert token in text
        assert "dashboard.serve --strict-port" in text
        assert "WantedBy=multi-user.target" in text

    def test_the_start_limit_sits_in_the_unit_section(self):
        """systemd reads StartLimitIntervalSec only under [Unit]; under
        [Service] it is ignored and the default 10 s window applies."""
        import configparser

        parser = configparser.ConfigParser(strict=False, interpolation=None)
        parser.optionxform = str  # systemd keys are case-sensitive
        parser.read_string(Path(__file__).resolve().parents[2].joinpath(
            "share/atlas-dashboard.service.in").read_text())
        for key in ("StartLimitIntervalSec", "StartLimitBurst"):
            assert key in parser["Unit"], key
            assert key not in parser["Service"], key

    def test_systemd_accepts_every_key_where_it_stands(self, tmp_path):
        """A key in a section that does not take it is ignored with only a log
        line: StartLimitIntervalSec under [Service] leaves the unit on the
        default 10 s window. Render the template the way install.sh does and
        let systemd read it."""
        import getpass
        import grp
        import os
        import re
        import shutil
        import subprocess
        import sys

        analyze = shutil.which("systemd-analyze")
        if not analyze:
            pytest.skip("systemd-analyze is not installed")
        repo = Path(__file__).resolve().parents[2]
        text = (repo / "share/atlas-dashboard.service.in").read_text()
        # The placeholders install.sh substitutes, from its own sed lines.
        tokens = set(re.findall(r'-e "s\|(@[A-Z_]+@)\|', (repo / "install.sh").read_text()))
        values = {"@USER@": getpass.getuser(), "@GROUP@": grp.getgrgid(os.getgid()).gr_name,
                  "@HOME@": str(Path.home()), "@ATLAS_DIR@": str(repo),
                  "@VENV_PY@": sys.executable, "@VENV_BIN@": str(Path(sys.executable).parent)}
        assert tokens == set(values), "install.sh substitutes other placeholders now"
        for token, value in values.items():
            text = text.replace(token, value)
        assert not re.search(r"@[A-Z_]+@", text), "a placeholder install.sh does not fill"
        def complaints(path):
            out = subprocess.run([analyze, "verify", str(path)], capture_output=True,
                                 text=True, timeout=120)
            # A parse complaint names the file and line ("<path>:30: Unknown key
            # …, ignoring."); what the host itself lacks (a bus, a cgroup) does not.
            return [line for line in (out.stdout + out.stderr).splitlines()
                    if line.startswith(f"{path}:")]

        # The check is only as good as systemd's wording: a key it cannot know
        # has to show up, or the empty result below would prove nothing.
        canary = tmp_path / "canary" / "atlas-dashboard.service"
        canary.parent.mkdir()
        canary.write_text(text.replace("[Service]\n", "[Service]\nNoSuchKeyAnywhere=1\n", 1))
        assert complaints(canary), "systemd-analyze no longer names the file in a complaint"
        unit = tmp_path / "atlas-dashboard.service"
        unit.write_text(text)
        assert not complaints(unit), complaints(unit)


class TestMainBindFlag:
    def test_bind_cli_reaches_serve(self, tmp_path, monkeypatch):
        from dashboard import serve as dash_serve

        seen: dict = {}

        def fake_serve(cases_root, port=8765, bind_host="127.0.0.1",
                       *, strict_port=False):
            seen["bind_host"] = bind_host
            seen["strict_port"] = strict_port
            seen["cases_root"] = cases_root
            return 0

        monkeypatch.setattr(dash_serve, "serve", fake_serve)
        rc = dash_serve.main(
            ["--bind", "0.0.0.0", "--strict-port",
             "--cases-root", str(tmp_path)])
        assert rc == 0
        assert seen["bind_host"] == "0.0.0.0"
        assert seen["strict_port"] is True

    def test_strict_port_defaults_false_without_flag(self, tmp_path, monkeypatch):
        # Regression: strict_port must come only from --strict-port, not
        # from stdin.isatty() — pytest itself runs with stdin not a tty,
        # so a tty-based fallback would make this assert True and mask
        # the bug that affected any non-interactive caller (cron, nohup).
        from dashboard import serve as dash_serve

        seen: dict = {}

        def fake_serve(cases_root, port=8765, bind_host="127.0.0.1",
                       *, strict_port=False):
            seen["strict_port"] = strict_port
            return 0

        monkeypatch.setattr(dash_serve, "serve", fake_serve)
        dash_serve.main(["--cases-root", str(tmp_path)])
        assert seen["strict_port"] is False
