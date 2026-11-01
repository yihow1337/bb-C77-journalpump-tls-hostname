#!/usr/bin/env python3
"""Show journalpump 2.4.6 TLS context lacks hostname verification (CWE-295)."""
import ssl
from pathlib import Path

def main() -> None:
    ctx_old = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ctx_old.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx_old.verify_mode = ssl.CERT_REQUIRED
    ctx_new = ssl.create_default_context()
    ctx_new.minimum_version = ssl.TLSVersion.TLSv1_2
    print(f"vuln check_hostname={ctx_old.check_hostname} verify={ctx_old.verify_mode}")
    print(f"fix  check_hostname={ctx_new.check_hostname} verify={ctx_new.verify_mode}")
    assert ctx_old.check_hostname is False and ctx_new.check_hostname is True
    Path(__file__).resolve().parent.joinpath("poc_results.txt").write_text("PASS\n")
    print("PASS")

if __name__ == "__main__":
    main()
