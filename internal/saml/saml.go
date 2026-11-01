// Package saml reads the AWS role attribute from a SAML response. It does not
// verify the signature; STS does.
package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
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
		r, err := parseRole(v)
		if err != nil {
			return nil, err
		}
		roles = append(roles, r)
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
		return Role{}, fmt.Errorf("SAML response has %d roles; set role_arn to choose one", len(roles))
	}
	for _, r := range roles {
		if r.RoleARN == roleARN {
			return r, nil
		}
	}
	return Role{}, fmt.Errorf("SAML response does not allow %s", roleARN)
}

// parseRole accepts both orders of "role,principal" that IdPs emit.
func parseRole(v string) (Role, error) {
	a, b, ok := strings.Cut(strings.TrimSpace(v), ",")
	if !ok {
		return Role{}, fmt.Errorf("malformed role attribute %q", v)
	}
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if strings.Contains(a, ":saml-provider/") {
		a, b = b, a
	}
	if !strings.Contains(a, ":role/") || !strings.Contains(b, ":saml-provider/") {
		return Role{}, fmt.Errorf("malformed role attribute %q", v)
	}
	return Role{RoleARN: a, PrincipalARN: b}, nil
}

func attributeValues(doc, name string) ([]string, error) {
	d := xml.NewDecoder(strings.NewReader(doc))
	var values []string
	inAttr, inValue := false, false
	var cur strings.Builder
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			return values, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parse SAML response: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case t.Name.Local == "Attribute":
				inAttr = attr(t, "Name") == name
			case inAttr && t.Name.Local == "AttributeValue":
				inValue = true
				cur.Reset()
			}
		case xml.CharData:
			if inValue {
				cur.Write(t)
			}
		case xml.EndElement:
			switch {
			case inValue && t.Name.Local == "AttributeValue":
				values = append(values, cur.String())
				inValue = false
			case t.Name.Local == "Attribute":
				inAttr = false
			}
		}
	}
}

func attr(e xml.StartElement, name string) string {
	for _, a := range e.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}
