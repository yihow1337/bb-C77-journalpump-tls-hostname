# C77 — journalpump 2.4.6: rsyslog TLS client omits hostname verification

## Program / asset
- **Program:** Aiven Bugcrowd (`aiven-mbb-og`), asset `github.com/Aiven-Open/journalpump`
- **Version:** 2.4.6 (`3e1b59c8`)
- **Unreleased fixes:** `766b860` (pass `server_hostname` for SNI); `652975d` (`ssl.create_default_context` → `check_hostname=True`)

## Root cause
```python
self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
self.ssl_context.verify_mode = ssl.CERT_REQUIRED
...
self.socket = self.ssl_context.wrap_socket(self.socket)  # no server_hostname
```
`SSLContext(PROTOCOL_TLS)` defaults `check_hostname=False`. With only `CERT_REQUIRED`, the chain is validated against the trust store but **the certificate CN/SAN need not match the server hostname**. If `cacerts` is unset and the process uses system CAs, any publicly trusted certificate enables MITM of the log pipeline.

Fingerprint: `journalpump | SyslogTcpClient TLS | SSL wrap without hostname check | CERT_REQUIRED + check_hostname=False | CWE-295 | MITM log stream | protocol=SSL/TLS rsyslog sender`

## Impact
Confidentiality/integrity of forwarded logs under active network attacker; credential theft if client certs used. **CVSS ~5.9 Medium** `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N` (AC:H = need MITM path). Higher if system CAs + no pinning.

## Distinctness
Same component as C75 but different sink (TLS handshake vs framing). Independent fix commits.

## Remediation
Release with `create_default_context` + `wrap_socket(..., server_hostname=self.server)`.

## Evidence
`EVIDENCE_C77.tar.gz`; `poc_tls_hostname.py`
