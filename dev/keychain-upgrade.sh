#!/bin/sh
# Writes a login Keychain item with one build, replaces the binary with
# another build signed the same way, and reads the item without a prompt.
# Without arguments it checks an ad-hoc and a self-signed signature, which
# both lose access. Pass an identity from your keychain, such as
# "Apple Development: ..." or "Developer ID Application: ...", to check it.
set -eu

cd "$(dirname "$0")/.."
work=$(mktemp -d)
kc="$work/test.keychain-db"
service=saml2sts.upgrade-test
cleanup() {
  # Another build cannot delete the item, but security(1) can.
  security delete-generic-password -s "$service" >/dev/null 2>&1 || true
  security delete-keychain "$kc" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# upgrade expect label [codesign args...] prints the partition ID macOS gave
# the item and fails unless the second build's read matches expect.
upgrade() {
  expect=$1 label=$2
  shift 2
  for v in 1 2; do
    go build -ldflags "-X main.build=$v" -o "$work/v$v" ./dev/keychain-upgrade
    [ $# -eq 0 ] || codesign -f -i saml2sts "$@" "$work/v$v" 2>/dev/null
  done
  cp "$work/v1" "$work/bin"
  "$work/bin" write
  partition=$(security dump-keychain -a 2>/dev/null |
    grep -A40 "\"svce\"<blob>=\"$service\"" | grep -Eo '(cdhash|teamid):[^ ]*' | head -1)
  cp "$work/v2" "$work/bin"
  if out=$("$work/bin" read 2>&1); then got=read; else got=lost; fi
  echo "$label: $got ($partition)"
  [ "$got" = "$expect" ] || echo "  expected $expect: $out" >&2
  security delete-generic-password -s "$service" >/dev/null 2>&1 || true
  [ "$got" = "$expect" ]
}

if [ $# -gt 0 ]; then
  upgrade read "$1" -s "$1"
  exit
fi

failed=0
upgrade lost "ad-hoc" || failed=1

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=saml2sts upgrade test" \
  -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=critical,codeSigning" \
  -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
# security(1) cannot import the default PKCS#12 encryption of OpenSSL 3.
openssl pkcs12 -export -legacy -passout pass:test -inkey "$work/key.pem" -in "$work/cert.pem" -out "$work/id.p12" 2>/dev/null ||
  openssl pkcs12 -export -passout pass:test -inkey "$work/key.pem" -in "$work/cert.pem" -out "$work/id.p12"
security create-keychain -p test "$kc"
security unlock-keychain -p test "$kc"
security import "$work/id.p12" -k "$kc" -P test -T /usr/bin/codesign >/dev/null
security set-key-partition-list -S apple-tool:,apple: -k test "$kc" >/dev/null
# The access list trusts the certificate, but the partition is still the cdhash.
upgrade lost "self-signed" -s "saml2sts upgrade test" --keychain "$kc" || failed=1
exit $failed
