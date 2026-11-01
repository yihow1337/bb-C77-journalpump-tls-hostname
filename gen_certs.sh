#!/usr/bin/env bash
# Regenerate throwaway CA + leaf certs for the C77 E2E PoC (local only).
set -euo pipefail
CERTS="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$CERTS"
openssl genrsa -out "$CERTS/ca.key" 2048
cat > "$CERTS/ca.cnf" <<'CNF'
[req]
distinguished_name=dn
x509_extensions=v3_ca
prompt=no
[dn]
CN=C77-Test-CA
[v3_ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
CNF
openssl req -new -x509 -key "$CERTS/ca.key" -out "$CERTS/ca.crt" -days 2 -sha256 -config "$CERTS/ca.cnf"

make_leaf() {
  local name="$1" out="$2"
  openssl genrsa -out "$CERTS/${out}.key" 2048
  openssl req -new -key "$CERTS/${out}.key" -out "$CERTS/${out}.csr" -subj "/CN=${name}"
  cat > "$CERTS/${out}.ext" <<EXT
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${name}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT
  openssl x509 -req -in "$CERTS/${out}.csr" -CA "$CERTS/ca.crt" -CAkey "$CERTS/ca.key" \
    -CAcreateserial -out "$CERTS/${out}.crt" -days 2 -sha256 -extfile "$CERTS/${out}.ext"
}
make_leaf "attacker.invalid" attacker
make_leaf "logs.victim.test" victim
echo "certs ready under $CERTS"
