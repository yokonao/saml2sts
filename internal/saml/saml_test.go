package saml

import (
	"encoding/base64"
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
