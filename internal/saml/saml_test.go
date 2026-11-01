package saml

import (
	"encoding/base64"
	"strings"
	"testing"
)

const response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
<saml:Assertion><saml:AttributeStatement>
<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName"><saml:AttributeValue>alice</saml:AttributeValue></saml:Attribute>
<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
<saml:AttributeValue>arn:aws:iam::111111111111:role/admin,arn:aws:iam::111111111111:saml-provider/idp</saml:AttributeValue>
</saml:Attribute>
<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
<saml:AttributeValue>arn:aws:iam::222222222222:saml-provider/idp, arn:aws:iam::222222222222:role/readonly</saml:AttributeValue>
</saml:Attribute>
</saml:AttributeStatement></saml:Assertion></samlp:Response>`

func TestRoles(t *testing.T) {
	roles, err := Roles(base64.StdEncoding.EncodeToString([]byte(response)))
	if err != nil {
		t.Fatal(err)
	}
	want := []Role{
		{"arn:aws:iam::111111111111:role/admin", "arn:aws:iam::111111111111:saml-provider/idp"},
		{"arn:aws:iam::222222222222:role/readonly", "arn:aws:iam::222222222222:saml-provider/idp"},
	}
	if len(roles) != len(want) {
		t.Fatalf("got %v", roles)
	}
	for i := range want {
		if roles[i] != want[i] {
			t.Errorf("roles[%d] = %v, want %v", i, roles[i], want[i])
		}
	}

	if _, err := Select(roles, ""); err == nil {
		t.Error("Select with two roles and no ARN should fail")
	}
	if r, err := Select(roles, want[1].RoleARN); err != nil || r != want[1] {
		t.Errorf("Select = %v, %v", r, err)
	}
	if _, err := Select(roles, "arn:aws:iam::333333333333:role/x"); err == nil {
		t.Error("Select with unknown ARN should fail")
	}
}

func TestRolesNone(t *testing.T) {
	if _, err := Roles(base64.StdEncoding.EncodeToString([]byte(`<Response/>`))); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseRoleRejectsMalformedARNs(t *testing.T) {
	const provider = "arn:aws:iam::111111111111:saml-provider/idp"
	for _, role := range []string{
		"arn:aws:iam::111111111111:role/admin\n[profile x]",
		"arn:aws:iam::111111111111:role/admin]",
		"arn:aws:iam::111111111111:role/ad min",
		"arn:aws:iam::111111111111:role/\x1b[31madmin",
		"arn:aws:iam::11111:role/admin",
		"arn:other:iam::111111111111:role/admin",
	} {
		if r, ok := parseRole(role + "," + provider); ok {
			t.Errorf("parseRole accepted %q: %v", role, r)
		}
	}
	if r, ok := parseRole("arn:aws:iam::111111111111:role/admin," + provider + "\n[x]"); ok {
		t.Errorf("parseRole accepted a provider with a newline: %v", r)
	}
	for _, v := range []string{
		"arn:aws:iam::111111111111:role/team/dev+ops=a,b@c," + provider,
		provider + ",arn:aws:iam::111111111111:role/a,b",
		"arn:aws-us-gov:iam::111111111111:role/admin,arn:aws-us-gov:iam::111111111111:saml-provider/idp",
	} {
		if _, ok := parseRole(v); !ok {
			t.Errorf("parseRole rejected %q", v)
		}
	}
}

func TestRolesOnlyFromTheAssertion(t *testing.T) {
	const role = `<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role"><saml:AttributeValue>arn:aws:iam::111111111111:role/admin,arn:aws:iam::111111111111:saml-provider/idp</saml:AttributeValue></saml:Attribute>`
	const head = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:x="urn:example">`
	for name, doc := range map[string]string{
		"in extensions":         head + `<samlp:Extensions>` + role + `</samlp:Extensions><saml:Assertion/></samlp:Response>`,
		"in another namespace":  head + `<saml:Assertion><saml:AttributeStatement><x:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role"><x:AttributeValue>arn:aws:iam::111111111111:role/admin,arn:aws:iam::111111111111:saml-provider/idp</x:AttributeValue></x:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`,
		"in a second assertion": head + `<saml:Assertion/><saml:Assertion><saml:AttributeStatement>` + role + `</saml:AttributeStatement></saml:Assertion></samlp:Response>`,
	} {
		if roles, err := Roles(base64.StdEncoding.EncodeToString([]byte(doc))); err == nil {
			t.Errorf("%s: got %v", name, roles)
		}
	}
}

func TestRolesEncrypted(t *testing.T) {
	doc := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:EncryptedAssertion/></samlp:Response>`
	_, err := Roles(base64.StdEncoding.EncodeToString([]byte(doc)))
	if err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("Roles = %v, want an error about encryption", err)
	}
}
