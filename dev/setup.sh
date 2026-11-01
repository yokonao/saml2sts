#!/bin/sh
# Registers the Keycloak realm as a SAML provider in floci and creates the
# roles the realm hands out. Run after `docker compose up -d`.
set -eu

keycloak=http://127.0.0.1:8080
floci=http://127.0.0.1:4566

until curl -sf -o /dev/null "$keycloak/realms/poc"; do sleep 2; done

iam() {
  curl -sf --aws-sigv4 aws:amz:us-east-1:iam --user test:test \
    --data-urlencode Version=2010-05-08 "$@" "$floci/" > /dev/null
}

metadata=$(curl -sf "$keycloak/realms/poc/protocol/saml/descriptor")
iam --data-urlencode Action=CreateSAMLProvider --data-urlencode Name=keycloak \
  --data-urlencode "SAMLMetadataDocument=$metadata"

# floci denies the SAML:aud condition AWS recommends, so it is left out.
trust='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::000000000000:saml-provider/keycloak"},"Action":"sts:AssumeRoleWithSAML"}]}'
for role in poc-admin poc-readonly; do
  iam --data-urlencode Action=CreateRole --data-urlencode "RoleName=$role" \
    --data-urlencode "AssumeRolePolicyDocument=$trust"
done
echo "floci trusts $keycloak/realms/poc"
