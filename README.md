## Summary

In journalpump 2.4.6, the rsyslog TLS client (`SyslogTcpClient`) builds an `ssl.SSLContext` with `CERT_REQUIRED` but never enables hostname verification and never passes `server_hostname` to `wrap_socket`. As a result, when `ca_certs` is configured, any certificate signed by that CA is accepted regardless of CN/SAN. An on-path attacker who can present such a certificate can intercept or alter the forwarded log stream.

This is fixed on the unreleased `master` branch (`766b860` adds `server_hostname`; `652975d` switches to `ssl.create_default_context`, which sets `check_hostname=True`). Neither commit is in any released tag as of this report (latest release: 2.4.6).

## Affected version

- **Package / repo:** [Aiven-Open/journalpump](https://github.com/Aiven-Open/journalpump)
- **Affected release:** 2.4.6 (git tag `2.4.6`, commit `3e1b59c8d95c1be8ad536088a389a3f36dec15a2`)
- **Component:** `journalpump/rsyslog.py` — class `SyslogTcpClient` (used by `journalpump.senders.rsyslog.RsyslogSender` when `ssl: true`)

## Vulnerable code

`journalpump/rsyslog.py` in 2.4.6:

```python
if cacerts is not None or protocol == "SSL":
    self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    self.ssl_context.verify_mode = ssl.CERT_REQUIRED
    if cacerts:
        self.ssl_context.load_verify_locations(cacerts)
    ...
# later, in _connect():
self.socket = self.ssl_context.wrap_socket(self.socket)  # no server_hostname=
```

`ssl.SSLContext(ssl.PROTOCOL_TLS)` defaults to `check_hostname=False`. With only `CERT_REQUIRED`, the client validates the certificate chain against the configured CA file but does **not** require the certificate identity to match the configured rsyslog server hostname.

## Steps to reproduce

All steps are local-only (loopback TLS listener, throwaway CA). No production hosts are contacted.

### 1. Obtain the vulnerable and fixed trees

```bash
git clone https://github.com/Aiven-Open/journalpump.git
cd journalpump
git checkout 2.4.6   # 3e1b59c8 — vulnerable
# keep a second worktree / checkout at 652975d for the fix comparison
```

### 2. Generate a throwaway CA and two leaf certificates

```bash
./gen_certs.sh
# produces:
#   certs/ca.crt                         (trust anchor)
#   certs/attacker.crt  CN/SAN=attacker.invalid
#   certs/victim.crt    CN/SAN=logs.victim.test
```

### 3. Run the end-to-end harness

```bash
python3 poc_e2e_tls_hostname.py
```

The harness:

1. Loads the real `SyslogTcpClient` from the 2.4.6 tree and from commit `652975d`.
2. Monkeypatches `socket.getaddrinfo` (harness only — not `/etc/hosts`) so the configured hostname `logs.victim.test` resolves to `127.0.0.1`.
3. Starts a local TLS listener presenting either the attacker or victim certificate.
4. Configures the client with `server=logs.victim.test`, `protocol=SSL`, `cacerts=<test CA>`, and sends one synthetic RFC5424 log line.

### 4. Observed results (from `poc_e2e_results.txt`)

| Case | Client | Server cert CN/SAN | Result |
|------|--------|--------------------|--------|
| Vulnerable mismatch | 2.4.6 | `attacker.invalid` | **Handshake succeeds; listener receives the synthetic log** |
| Fixed mismatch | `652975d` | `attacker.invalid` | **Rejected:** `Hostname mismatch, certificate is not valid for 'logs.victim.test'` |
| Vulnerable match (negative control) | 2.4.6 | `logs.victim.test` | Handshake succeeds; log delivered |
| Fixed match (negative control) | `652975d` | `logs.victim.test` | Handshake succeeds; log delivered |

Key vulnerable-case excerpt:

```
client=handshake+send ok
recv=b'<14>1 ... c77-poc 1 C77 C77-SYNTHETIC-LOG-LINE-DO-NOT-SUBMIT\n'
```

Key fixed-case excerpt:

```
SSLCertVerificationError: ... Hostname mismatch, certificate is not valid for 'logs.victim.test'.
```

Verdict line from the harness: `VERDICT: VULN CONFIRMED E2E`

## Expected behavior

The TLS client must verify that the presented certificate’s identity matches the configured server hostname (e.g. via `ssl.create_default_context` + `wrap_socket(..., server_hostname=self.server)`). A certificate for `attacker.invalid` must not be accepted for `logs.victim.test`.

## Impact

- **CWE-295:** Improper Certificate Validation
- **CVSS 3.1 (estimated): 5.9 Medium** — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N`
  - **AC:H** — attacker needs an on-path (MITM) network position between journalpump and the rsyslog destination.
  - Confidentiality of forwarded logs is lost if the attacker terminates TLS.
  - Integrity is partially affected (attacker can drop/modify/inject records on the wire).
- Realistic prerequisite: `ssl: true` with `ca_certs` pointing at a CA (or CA bundle) that also issued, or can be induced to issue, a certificate the attacker controls. If `ca_certs` is a broad bundle (for example a system CA bundle), any name under that trust set works for MITM. If it is an organization-private CA, the attacker needs a leaf from that CA (mis-issuance, compromised leaf, or access to the CA).
- Note: with `protocol=SSL` and **no** `ca_certs`, 2.4.6 sets `CERT_REQUIRED` but loads no trust anchors, so handshakes fail closed. The hostname bug is material when TLS is actually operational (i.e. when `ca_certs` is set).

## Fix reference (unreleased)

Already on `master`, not in any release tag:

1. [`766b860`](https://github.com/Aiven-Open/journalpump/commit/766b860) — pass `server_hostname=self.server` into `wrap_socket` (SNI + identity).
2. [`652975d`](https://github.com/Aiven-Open/journalpump/commit/652975d) (merge [`34900c9`](https://github.com/Aiven-Open/journalpump/commit/34900c9)) — replace `ssl.SSLContext(ssl.PROTOCOL_TLS)` with `ssl.create_default_context(cafile=cacerts)`, which enables `check_hostname=True` by default.

## Remediation

- Release a new journalpump version containing the above commits.
- Until then, operators should treat the rsyslog TLS path as authenticating the CA only, not the hostname, and restrict `ca_certs` to the narrowest possible trust anchor; prefer network controls that make on-path attack impractical.

## Evidence

Attached / accompanying package includes:

- `poc_e2e_tls_hostname.py` — deterministic end-to-end harness using real `SyslogTcpClient`
- `poc_e2e_results.txt` — full run log with `VERDICT: VULN CONFIRMED E2E`
- `evidence/rsyslog_2.4.6.py` / `evidence/rsyslog_master.py` — exact vulnerable and fixed module copies
- `evidence/VERSIONS.txt` — commits, file SHA-256 digests, toolchain versions
- `gen_certs.sh` + public test certificates (private keys excluded; regenerate locally)
