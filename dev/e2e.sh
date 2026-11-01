#!/bin/sh
# Runs the login flow against dev/compose.yml with curl standing in for the
# browser and extension: login -> Keycloak sign-in -> native host -> floci STS.
# It starts as a new user would, with profiles sync, then signs in for a named
# role and for a role chosen afterwards.
set -eu

cd "$(dirname "$0")/.."
work=$(mktemp -d)
bin="$work/saml2sts"
login_pid=
cleanup() {
  kill $login_pid 2>/dev/null || true
  # Each build is a new binary to the Keychain access list, so drop what this one wrote.
  [ -x "$bin" ] && "$bin" logout --all
  rm -rf "$work"
}
trap cleanup EXIT

go build -o "$bin" ./cmd/saml2sts

cat > "$work/config.toml" <<'EOF'
[idp]
url = "http://127.0.0.1:8080/realms/poc/protocol/saml/clients/aws"
duration = "1h"
sts_endpoint = "http://127.0.0.1:4566"

[roles]
poc-admin = "arn:aws:iam::000000000000:role/poc-admin"
poc-readonly = "arn:aws:iam::000000000000:role/poc-readonly"
EOF
export SAML2STS_CONFIG="$work/config.toml"

jar="$work/cookies"
# sign_in leaves Keycloak's auto-submitting SAML form in $work/post.html,
# signing in as alice unless the cookie jar still holds a session.
sign_in() {
  curl -sf -c "$jar" -b "$jar" "http://127.0.0.1:8080/realms/poc/protocol/saml/clients/aws" > "$work/post.html"
  if grep -q kc-form-login "$work/post.html"; then
    action=$(python3 -I -c 'import html,re,sys; print(html.unescape(re.search(r"id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"", open(sys.argv[1]).read()).group(1)))' "$work/post.html")
    curl -sf -c "$jar" -b "$jar" --data-urlencode username=alice --data-urlencode password=alice "$action" > "$work/post.html"
  fi
}

# nonce prints the nonce of the IdP URL the waiting login printed to $work/login.log.
nonce() {
  sed -n 's/.*#saml2sts=\([^&]*\).*/\1/p' "$work/login.log" | tail -n 1
}

# deliver hands the SAML response to the native host as the extension would,
# with the nonce in $1.
deliver() {
  python3 -I -c '
import html, json, re, struct, sys
v = html.unescape(re.search(r"name=\"SAMLResponse\"\s+value=\"([^\"]+)\"", open(sys.argv[1]).read()).group(1))
d = json.dumps({"samlResponse": v, "nonce": sys.argv[2]}).encode()
sys.stdout.buffer.write(struct.pack("=I", len(d)) + d)
' "$work/post.html" "$1" | "$bin" chrome-extension://ljanpcedhfnidohflcgdjflhhjebpikb/ | python3 -I -c '
import json, struct, sys
b = sys.stdin.buffer.read()
while b:
    n = struct.unpack("=I", b[:4])[0]
    print("host:", json.loads(b[4:4 + n]))
    b = b[4 + n:]
'
}

export AWS_CONFIG_FILE="$work/aws-config"

echo "--- profiles sync, reading the roles"
"$bin" profiles sync --refresh --no-open --timeout 20s \
  --path "$bin" --region us-east-1 --endpoint-url http://127.0.0.1:4566 2> "$work/login.log" &
login_pid=$!
sleep 1
sign_in
echo "a SAML response without the login's nonce is ignored:"
deliver "" | tee "$work/host.log"
grep -q "'idle'" "$work/host.log"
deliver "$(nonce)"
wait $login_pid
cat "$work/login.log" >&2
grep '^\[profile' "$AWS_CONFIG_FILE"
if "$bin" creds --role poc-admin --no-open --timeout 2s > /dev/null 2>&1; then
  echo "profiles sync left credentials behind" >&2
  exit 1
fi
echo "no role was assumed"

echo "--- login --role poc-admin, with the SAML response delivered twice at once"
"$bin" login --role poc-admin --no-open --timeout 20s 2> "$work/login.log" &
login_pid=$!
sleep 1
sign_in
deliver "$(nonce)" > "$work/host1.log" &
deliver_pid=$!
deliver "$(nonce)" > "$work/host2.log"
wait $deliver_pid
cat "$work/host1.log" "$work/host2.log"
[ "$(cat "$work/host1.log" "$work/host2.log" | grep -c "'ok'")" = 1 ]
wait $login_pid
cat "$work/login.log" >&2

echo "--- login, choosing the role afterwards"
printf '2\n' | "$bin" login --no-open --timeout 20s 2> "$work/login.log" &
login_pid=$!
sleep 1
sign_in
deliver "$(nonce)"
wait $login_pid
cat "$work/login.log" >&2
login_pid=

echo "--- roles"
"$bin" roles

echo "--- the AWS CLI through the profiles"
for profile in saml2sts-poc-admin saml2sts-poc-readonly; do
  aws sts get-caller-identity --profile $profile --query Arn --output text
done

echo "--- credential_process output (from the cache)"
"$bin" creds --role poc-admin --timeout 5s | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print({k: (v if k in ("Version","Expiration") else v[:8]+"...") for k, v in d.items()})'

echo "--- GetCallerIdentity with exec, for each role"
for role in poc-admin poc-readonly; do
"$bin" exec --role $role --timeout 5s -- sh -c 'curl -sf --aws-sigv4 aws:amz:us-east-1:sts \
  --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \
  -H "x-amz-security-token: $AWS_SESSION_TOKEN" \
  -d "Action=GetCallerIdentity&Version=2011-06-15" http://127.0.0.1:4566/' | grep -o '<Arn>[^<]*</Arn>'
done
