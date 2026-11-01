// Package saml reads the AWS role attribute from a SAML response. It does not
// verify the signature; STS does.
package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const roleAttribute = "https://aws.amazon.com/SAML/Attributes/Role"

// Role is a role the assertion allows, paired with the IdP it trusts.
type Role struct {
	RoleARN      string `json:"role_arn"`
	PrincipalARN string `json:"principal_arn"`
}

// Roles returns the roles in a base64-encoded SAML response.
func Roles(samlResponse string) ([]Role, error) {
	raw, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, fmt.Errorf("decode SAML response: %w", err)
	}
	values, err := attributeValues(string(raw), roleAttribute)
	if err != nil {
		return nil, err
	}
	var roles []Role
	for _, v := range values {
		if r, ok := parseRole(v); ok {
			roles = append(roles, r)
		}
	}
	if len(roles) == 0 {
		return nil, errors.New("SAML response has no AWS role")
	}
	return roles, nil
}

// Select returns the role with roleARN, or the only role when roleARN is empty.
func Select(roles []Role, roleARN string) (Role, error) {
	if roleARN == "" {
		if len(roles) == 1 {
			return roles[0], nil
		}
		return Role{}, fmt.Errorf("SAML response has %d roles; pass --role to choose one", len(roles))
	}
	for _, r := range roles {
		if r.RoleARN == roleARN {
			return r, nil
		}
	}
	return Role{}, fmt.Errorf("SAML response does not allow %s", roleARN)
}

var (
	roleARN     = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]+$`)
	providerARN = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:saml-provider/[\w.-]+$`)
)

// Valid reports whether both ARNs are well formed, so they are safe to print
// or to write into the AWS config file.
func (r Role) Valid() bool {
	return roleARN.MatchString(r.RoleARN) && providerARN.MatchString(r.PrincipalARN)
}

// parseRole accepts both orders of "role,principal" that IdPs emit. The SAML
// response is not verified yet, so it rejects anything but well-formed ARNs.
func parseRole(v string) (Role, bool) {
	v = strings.TrimSpace(v)
	// A role name may contain commas, a provider name may not.
	if i := strings.LastIndex(v, ","); i >= 0 {
		if r, ok := role(v[:i], v[i+1:]); ok {
			return r, true
		}
	}
	if i := strings.Index(v, ","); i >= 0 {
		return role(v[i+1:], v[:i])
	}
	return Role{}, false
}

func role(arn, provider string) (Role, bool) {
	r := Role{RoleARN: strings.TrimSpace(arn), PrincipalARN: strings.TrimSpace(provider)}
	return r, r.Valid()
}

type samlResponse struct {
	XMLName    xml.Name    `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	Assertions []assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	Encrypted  []struct{}  `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`
}

type assertion struct {
	Statements []struct {
		Attributes []struct {
			Name   string   `xml:"Name,attr"`
			Values []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

// attributeValues reads the attribute from the one assertion that AWS takes,
// only where SAML puts it, so values elsewhere in the document are ignored.
func attributeValues(doc, name string) ([]string, error) {
	var r samlResponse
	if err := xml.Unmarshal([]byte(doc), &r); err != nil {
		return nil, fmt.Errorf("parse SAML response: %w", err)
	}
	if len(r.Encrypted) > 0 {
		return nil, errors.New("SAML response has an encrypted assertion, which saml2sts cannot read; ask your IdP admin to turn off assertion encryption for AWS")
	}
	if len(r.Assertions) != 1 {
		return nil, fmt.Errorf("SAML response has %d assertions, want 1", len(r.Assertions))
	}
	var values []string
	for _, st := range r.Assertions[0].Statements {
		for _, a := range st.Attributes {
			if a.Name == name {
				values = append(values, a.Values...)
			}
		}
	}
	return values, nil
}
