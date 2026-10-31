#!/usr/bin/env bash
# Generate a throwaway test PKI for manual lab testing (TEST_PLAN TestPki): a CA and a leaf for
# the given host names. Output: <dir>/{ca.pem,ca.key,leaf.pem,leaf.key}. Lab use only; never
# install this CA outside your own test browser profile (D-30). Automated tests use rcgen instead.
set -euo pipefail
dir=${1:?usage: gen_test_pki.sh <out-dir> [host...]}
shift
hosts=("${@:-localhost}")
mkdir -p "$dir"
chmod 700 "$dir"
umask 077
openssl ecparam -name prime256v1 -genkey -noout -out "$dir/ca.key"
openssl req -x509 -new -key "$dir/ca.key" -sha256 -days 30 -subj "/CN=webfilter manual test CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$dir/ca.pem"
san=$(printf 'DNS:%s,' "${hosts[@]}"); san=${san%,}
openssl ecparam -name prime256v1 -genkey -noout -out "$dir/leaf.key"
openssl req -new -key "$dir/leaf.key" -subj "/CN=${hosts[0]}" -out "$dir/leaf.csr"
openssl x509 -req -in "$dir/leaf.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca.key" -CAcreateserial -days 7 -sha256 \
    -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$san") -out "$dir/leaf.pem"
rm -f "$dir/leaf.csr" "$dir/ca.srl"
echo "test PKI in $dir (CA: ca.pem; leaf for: ${hosts[*]})"
