// Package store holds the secure storage items through which the CLI and the
// native messaging host, which the browser starts, hand a login to each other:
//
//	login: writes Pending, then polls for Result
//	host:  reads Pending; for ListOnly, saves the roles and writes Result{Listed}
//	host:  without a role, writes Result{Roles} and polls for Choice
//	login: answers Roles with a Choice
//	host:  calls STS, writes Result{Credentials}, deletes Pending
//	login: checks Result's secret, caches the credentials under the role ARN
package store

import (
	"encoding/json"
	"time"

	"github.com/yokonao/saml2sts/internal/federation"
	"github.com/yokonao/saml2sts/internal/keychain"
	"github.com/yokonao/saml2sts/internal/saml"
)

const service = "saml2sts"

var (
	pendingItem = keychain.Item{Service: service + ".pending", Account: "login"}
	resultItem  = keychain.Item{Service: service + ".result", Account: "login"}
	choiceItem  = keychain.Item{Service: service + ".choice", Account: "login"}
	rolesItem   = keychain.Item{Service: service + ".roles", Account: "login"}
)

func cacheItem(roleARN string) keychain.Item {
	return keychain.Item{Service: service + ".credentials", Account: roleARN}
}

// Pending is a login waiting for a SAML response.
type Pending struct {
	// RoleARN is the role to assume; empty asks the user to choose one of the
	// roles in the SAML response.
	RoleARN string `json:"role_arn,omitempty"`
	// ListOnly asks only for the roles the IdP allows, assuming none.
	ListOnly bool `json:"list_only,omitempty"`
	// Secret is echoed in Result and Choice, so neither side accepts an item
	// planted by a program that cannot read this one.
	Secret  string    `json:"secret"`
	Expires time.Time `json:"expires"`
}

// Result is the host's answer to a Pending login: the roles to choose from,
// credentials, or an error.
type Result struct {
	Secret      string                  `json:"secret"`
	Roles       []saml.Role             `json:"roles,omitempty"`
	Credentials *federation.Credentials `json:"credentials,omitempty"`
	RoleARN     string                  `json:"role_arn,omitempty"`
	// Listed answers a ListOnly login: the roles are saved.
	Listed bool   `json:"listed,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Choice is the user's pick among Result.Roles.
type Choice struct {
	Secret  string `json:"secret"`
	RoleARN string `json:"role_arn"`
}

// WritePending replaces the pending login and clears what an earlier one left.
func WritePending(p Pending) error {
	for _, item := range []keychain.Item{resultItem, choiceItem} {
		if err := keychain.Delete(item); err != nil {
			return err
		}
	}
	return write(pendingItem, p)
}

// ReadPending returns nil when no login is pending.
func ReadPending() (*Pending, error) { return read[Pending](pendingItem) }

// DeletePending ends the pending login.
func DeletePending() error { return keychain.Delete(pendingItem) }

// WriteResult answers the pending login.
func WriteResult(r Result) error { return write(resultItem, r) }

// ReadResult returns nil while the host has not answered.
func ReadResult() (*Result, error) { return read[Result](resultItem) }

// DeleteResult consumes the answer.
func DeleteResult() error { return keychain.Delete(resultItem) }

// WriteChoice answers a Result listing roles.
func WriteChoice(c Choice) error { return write(choiceItem, c) }

// ReadChoice returns nil while the user has not chosen.
func ReadChoice() (*Choice, error) { return read[Choice](choiceItem) }

// DeleteChoice consumes the choice.
func DeleteChoice() error { return keychain.Delete(choiceItem) }

// WriteRoles remembers the roles the last SAML response allowed.
func WriteRoles(roles []saml.Role) error { return write(rolesItem, roles) }

// ReadRoles returns the roles the last SAML response allowed, or nil.
func ReadRoles() ([]saml.Role, error) {
	r, err := read[[]saml.Role](rolesItem)
	if r == nil || err != nil {
		return nil, err
	}
	return *r, nil
}

// ReadCache returns nil when the role has no cached credentials.
func ReadCache(roleARN string) (*federation.Credentials, error) {
	return read[federation.Credentials](cacheItem(roleARN))
}

// WriteCache caches c for the role.
func WriteCache(roleARN string, c federation.Credentials) error {
	return write(cacheItem(roleARN), c)
}

// DeleteCache drops the cached credentials of the role.
func DeleteCache(roleARN string) error { return keychain.Delete(cacheItem(roleARN)) }

// Forget drops the cached credentials of every role and the list of roles.
func Forget() error {
	if err := keychain.DeleteService(service + ".credentials"); err != nil {
		return err
	}
	return keychain.Delete(rolesItem)
}

func write(item keychain.Item, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return keychain.Write(item, b)
}

func read[T any](item keychain.Item) (*T, error) {
	b, err := keychain.Read(item)
	if b == nil || err != nil {
		return nil, err
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}
