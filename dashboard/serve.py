#!/usr/bin/env python3
"""Persistent multi-case Atlas dashboard server — the launcher.

The application itself (routes, sessions, read models, static files) is
``dashboard/app.py``; this module binds it with uvicorn, resolves TLS and
the Host allowlist, writes the discovery file and owns the CLI.

Serves a cases root directory (default ~/cases) as the document root.
The dashboard HTML and vendor assets are served from the atlas/dashboard/
source dir under the ``/_dashboard/`` URL prefix, so the dashboard is
available even when no investigation is running and a freshly written
trace.json shows up in the dropdown without restarting the server.

Usage:
    atlas-dashboard [--cases-root DIR] [--demo|--benchmarks] [--port N] [--bind ADDR]
    python -m dashboard.serve [--cases-root DIR] [--demo|--benchmarks] [--port N] [--bind ADDR]

Environment overrides:
    ATLAS_CASES_ROOT           default for --cases-root (fallback: ~/cases)
    ATLAS_DASHBOARD_PORT       default for --port      (fallback: 8765)
    ATLAS_DASHBOARD_BIND       default for --bind      (fallback: 127.0.0.1)
    ATLAS_DASHBOARD_TLS_CERT   admin/org certificate (PEM)
    ATLAS_DASHBOARD_TLS_KEY    matching private key (PEM, mode 0600)
    ATLAS_DASHBOARD_EXTRA_HOSTS  extra Host names (comma-separated)

Convenience roots (repo-relative):
    --demo         serve Atlas/demo-cases (bundled example studies)
    --benchmarks   serve Atlas/benchmarks (ground_truth grading sets)
    Production investigations always default to ~/cases.

Binds 127.0.0.1 (HTTP) by default. A non-loopback --bind (typically
0.0.0.0 for LAN) is HTTPS-only. On startup writes ~/.cache/atlas/dashboard.url
so other Atlas components can discover the running dashboard without taking
a port for themselves. That discovery URL is always the loopback address.
"""
from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()  # must run before core.mail reads SMTP config from os.environ

import argparse
import atexit
import json
import os
import socket
import ssl
import sys
import threading
from pathlib import Path

import uvicorn

from core.envfile import env_int
from dashboard import auth
from dashboard import listen
from dashboard.app import (  # noqa: F401 — re-exported for callers of the old layout
    API_PREFIX, DASHBOARD_PREFIX, DASHBOARD_SRC, SESSION_COOKIE,
    case_token_totals, create_app, list_cases,
)

DEFAULT_PORT = env_int("ATLAS_DASHBOARD_PORT", 8765)
DEFAULT_BIND = os.environ.get("ATLAS_DASHBOARD_BIND", "127.0.0.1")
DEFAULT_CASES_ROOT = os.environ.get(
    "ATLAS_CASES_ROOT",
    os.path.expanduser("~/cases"),
)
DISCOVERY_FILE = os.path.expanduser("~/.cache/atlas/dashboard.url")


class _DashboardServer:
    """uvicorn behind the socketserver-shaped surface serve() and the tests
    drive: bind now (so a taken port fails here, not later), serve_forever()
    on the calling thread, shutdown() from another.

    uvicorn brings what the stdlib server lacked: HTTP/1.1 keep-alive (one
    connection per tab instead of one per request), TLS handshakes in the
    event loop instead of on the accept thread, idle and graceful-shutdown
    timeouts, and clean SIGTERM handling.
    """

    def __init__(self, app, host: str, port: int, *,
                 tls: tuple[Path, Path] | None = None):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.socket = socket.socket(family, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.bind((host, port))
        except OSError:
            self.socket.close()
            raise
        # A page navigation opens a burst of connections; with keep-alive it
        # is a small one, but the queue still has to hold it.
        self.socket.listen(128)
        self.socket.set_inheritable(True)
        self.server_address = self.socket.getsockname()[:2]

        tls_kwargs: dict = {}
        if tls is not None:
            cert, key = tls
            # Built now so a bad key or file mode fails at bind time, and
            # handed to uvicorn as-is: same minimum TLS version and cert
            # chain the stdlib server used.
            context = listen.make_tls_context(cert, key)
            tls_kwargs = dict(
                ssl_certfile=str(cert), ssl_keyfile=str(key),
                ssl_context_factory=lambda _config, _default: context)
        config = uvicorn.Config(
            app, host=host, port=self.server_address[1],
            log_level="info", server_header=False,
            timeout_keep_alive=5, timeout_graceful_shutdown=10,
            **tls_kwargs)
        self._server = uvicorn.Server(config)
        self._done = threading.Event()

    def serve_forever(self) -> None:
        try:
            self._server.run(sockets=[self.socket])
        finally:
            self._done.set()

    def shutdown(self) -> None:
        self._server.should_exit = True
        self._done.wait(15)

    def server_close(self) -> None:
        self.socket.close()


def _bind(
    cases_root: str,
    port: int,
    host: str = "127.0.0.1",
    *,
    strict_port: bool = False,
    use_tls: bool = False,
    host_allowlist: frozenset[str] | None = None,
    tls: tuple[Path, Path] | None = None,
) -> tuple[_DashboardServer, int]:
    allow = (host_allowlist if host_allowlist is not None
             else listen.build_host_allowlist(host))
    app = create_app(cases_root, use_tls=use_tls, host_allowlist=allow)
    last_err = ""
    # port=0 → kernel picks a free port; one attempt is enough. Otherwise
    # fall through up to +19 on collision unless strict_port (systemd).
    if port == 0:
        candidates = [0]
    elif strict_port:
        candidates = [port]
    else:
        candidates = range(port, port + 20)
    for candidate in candidates:
        try:
            httpd = _DashboardServer(app, host, candidate, tls=tls)
            return httpd, httpd.server_address[1]
        except OSError as e:
            last_err = str(e)
    span = str(port) if strict_port or port == 0 else f"{port}..{port + 19}"
    raise OSError(f"no free port in {span}: {last_err}")


def _write_discovery(url: str, port: int, cases_root: str) -> None:
    try:
        os.makedirs(os.path.dirname(DISCOVERY_FILE), exist_ok=True)
        with open(DISCOVERY_FILE, "w") as f:
            f.write(json.dumps({
                "url": url,
                "port": port,
                "cases_root": cases_root,
                "pid": os.getpid(),
            }) + "\n")
    except OSError as e:
        print(f"warn: could not write discovery file {DISCOVERY_FILE}: {e}",
              file=sys.stderr)


def _clear_discovery() -> None:
    try:
        os.remove(DISCOVERY_FILE)
    except OSError:
        pass


def _close_chat_workers() -> None:
    """Terminate any chat worker subprocesses so they don't orphan when the
    dashboard exits. Only touches the manager if the chat module was imported
    (i.e. a chat endpoint was actually hit this run)."""
    mod = sys.modules.get("dashboard.chat")
    if mod is not None:
        try:
            mod.MANAGER.close_all()
        except Exception:  # noqa: BLE001
            pass


def _close_run_workers() -> None:
    """Same idea as _close_chat_workers, for dashboard-started investigation
    runs — never leave one orphaned when the dashboard process exits."""
    mod = sys.modules.get("dashboard.run_manager")
    if mod is not None:
        try:
            mod.MANAGER.close_all()
        except Exception:  # noqa: BLE001
            pass


def serve(
    cases_root: str,
    port: int = DEFAULT_PORT,
    bind_host: str = "127.0.0.1",
    *,
    strict_port: bool = False,
) -> int:
    cases_root = os.path.abspath(os.path.expanduser(cases_root))
    if not os.path.isdir(cases_root):
        sys.exit(f"cases_root not a directory: {cases_root}")
    try:
        bind_host = listen.parse_bind_host(bind_host)
    except ValueError as exc:
        sys.exit(f"atlas-dashboard: {exc}")
    use_tls = listen.tls_required(bind_host)
    extra = os.environ.get("ATLAS_DASHBOARD_EXTRA_HOSTS", "")
    allow = listen.build_host_allowlist(bind_host, extra=extra)

    tls_material = None
    if use_tls:
        try:
            tls_material = listen.resolve_tls_files(
                bind_host,
                env_cert=os.environ.get("ATLAS_DASHBOARD_TLS_CERT") or None,
                env_key=os.environ.get("ATLAS_DASHBOARD_TLS_KEY") or None,
            )
        except listen.TlsError as exc:
            sys.exit(f"atlas-dashboard: {exc}")

    auth.init_db()
    tls = None
    if tls_material is not None:
        cert, key, generated = tls_material
        tls = (cert, key)
    try:
        httpd, chosen = _bind(
            cases_root, port, bind_host, strict_port=strict_port,
            use_tls=use_tls, host_allowlist=allow, tls=tls)
    except (listen.TlsError, ssl.SSLError) as exc:
        sys.exit(f"atlas-dashboard: TLS setup failed: {exc}")
    if tls_material is not None and generated:
        print(f"warn: generated a self-signed TLS certificate at {cert}",
              file=sys.stderr)
        print(f"  SHA-256 fingerprint: {listen.cert_sha256_fingerprint(cert)}",
              file=sys.stderr)
        print("  Replace with an organisation certificate: "
              "/etc/atlas/dashboard/tls.crt + tls.key "
              "(or ATLAS_DASHBOARD_TLS_CERT / ATLAS_DASHBOARD_TLS_KEY)",
              file=sys.stderr)

    scheme = "https" if use_tls else "http"
    url = f"{scheme}://127.0.0.1:{chosen}{DASHBOARD_PREFIX}dashboard.html"
    _write_discovery(url, chosen, cases_root)
    discovered = list_cases(cases_root)
    print(f"\nAtlas dashboard")
    print(f"  cases_root: {cases_root}")
    print(f"  bind: {bind_host}:{chosen} ({'HTTPS' if use_tls else 'HTTP'})")
    print(f"  URL: {url}")
    if not listen.is_loopback_bind(bind_host):
        lan_shown = False
        for ip in listen.local_ipv4_addresses():
            if ip in ("127.0.0.1", "0.0.0.0"):
                continue
            print(f"  LAN: {scheme}://{ip}:{chosen}{DASHBOARD_PREFIX}dashboard.html")
            lan_shown = True
        if not lan_shown:
            print(f"  LAN: {scheme}://<this-host-ip>:{chosen}"
                  f"{DASHBOARD_PREFIX}dashboard.html")
        print("  Restrict this port to your LAN — Atlas does not open the firewall.")
        publics = listen.public_addresses()
        if publics:
            print(f"warn: this host has a public address "
                  f"({', '.join(publics)}); the dashboard will be reachable "
                  f"there unless the firewall blocks it", file=sys.stderr)
        if not auth.has_any_users():
            print("warn: no admin yet — the first visitor to create an "
                  "account becomes admin", file=sys.stderr)
    if discovered:
        names = ", ".join(c["case_id"] for c in discovered)
        print(f"  cases: {len(discovered)} ({names})")
    else:
        print("  cases: 0 — drop a case dir under cases_root and it will appear "
              "in the dropdown")
    print("Press Ctrl-C to stop.\n", flush=True)
    # uvicorn turns SIGINT/SIGTERM into a graceful stop (open requests get
    # timeout_graceful_shutdown to finish); serve_forever() then returns and
    # the atexit cleanup below runs.
    atexit.register(_clear_discovery)
    atexit.register(_close_chat_workers)
    atexit.register(_close_run_workers)
    try:
        httpd.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        print("\nShutting down.", file=sys.stderr)
    return 0


def _repo_root() -> str:
    return os.path.dirname(DASHBOARD_SRC)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="atlas-dashboard",
        description="Persistent Atlas trace dashboard (multi-case).",
    )
    parser.add_argument(
        "--cases-root",
        default=None,
        help=(f"root dir containing case subdirectories "
              f"(default: {DEFAULT_CASES_ROOT}; env ATLAS_CASES_ROOT)"),
    )
    root_grp = parser.add_mutually_exclusive_group()
    root_grp.add_argument(
        "--demo", action="store_true",
        help="serve Atlas/demo-cases (bundled example studies)",
    )
    root_grp.add_argument(
        "--benchmarks", action="store_true",
        help="serve Atlas/benchmarks (ground_truth grading sets)",
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=(f"starting port; falls through up to +19 on collision "
              f"unless --strict-port (default: {DEFAULT_PORT}; "
              f"env ATLAS_DASHBOARD_PORT)"),
    )
    parser.add_argument(
        "--bind", default=None,
        help=(f"listen address (default: {DEFAULT_BIND}; "
              f"env ATLAS_DASHBOARD_BIND). 127.0.0.1 is HTTP; any "
              f"non-loopback address is HTTPS-only"),
    )
    parser.add_argument(
        "--strict-port", action="store_true",
        help="fail if --port is taken instead of trying the next 19 ports "
             "(systemd's atlas-dashboard.service always passes this)",
    )
    args = parser.parse_args(argv)
    if args.demo:
        cases_root = os.path.join(_repo_root(), "demo-cases")
    elif args.benchmarks:
        cases_root = os.path.join(_repo_root(), "benchmarks")
    else:
        cases_root = args.cases_root or DEFAULT_CASES_ROOT
    bind_host = args.bind or os.environ.get("ATLAS_DASHBOARD_BIND", "127.0.0.1")
    return serve(
        cases_root, port=args.port, bind_host=bind_host,
        strict_port=args.strict_port)


if __name__ == "__main__":
    raise SystemExit(main())
