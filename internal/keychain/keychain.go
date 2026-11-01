//go:build darwin

// Package keychain stores generic passwords in the login Keychain, where
// SecItemAdd's default access list trusts only the running binary.
package keychain

import (
	"errors"
	"fmt"
	"maps"

	"github.com/yokonao/appleframeworks/security"
)

// Item names a generic password.
type Item struct {
	Service string
	Account string
}

func query(item Item, extra security.Attrs) security.Attrs {
	q := security.Attrs{
		security.Class:       security.ClassGenericPassword,
		security.AttrService: item.Service,
		security.AttrAccount: item.Account,
	}
	maps.Copy(q, extra)
	return q
}

// Read returns nil without an error when the item does not exist.
func Read(item Item) ([]byte, error) {
	data, err := security.CopyMatching(query(item, security.Attrs{security.ReturnData: true, security.MatchLimit: security.MatchLimitOne}))
	if errors.Is(err, security.ErrItemNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s from Keychain: %w", item.Service, err)
	}
	return data.([]byte), nil
}

// Write replaces the item. It deletes before adding instead of updating, since
// an update keeps the access list of an item another program may have planted.
func Write(item Item, value []byte) error {
	if err := Delete(item); err != nil {
		return err
	}
	if _, err := security.Add(query(item, security.Attrs{security.ValueData: value})); err != nil {
		return fmt.Errorf("store %s in Keychain: %w", item.Service, err)
	}
	return nil
}

// Delete succeeds when the item does not exist.
func Delete(item Item) error {
	if err := security.Delete(query(item, nil)); err != nil && !errors.Is(err, security.ErrItemNotFound) {
		return fmt.Errorf("remove %s from Keychain: %w", item.Service, err)
	}
	return nil
}

// DeleteService removes every item of service, whatever its account.
func DeleteService(service string) error {
	q := security.Attrs{security.Class: security.ClassGenericPassword, security.AttrService: service}
	// The login Keychain deletes one matching item per call.
	for {
		err := security.Delete(q)
		if errors.Is(err, security.ErrItemNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("remove %s from Keychain: %w", service, err)
		}
	}
}

// Accounts lists the accounts of service's items, without reading their data.
func Accounts(service string) ([]string, error) {
	res, err := security.CopyMatching(security.Attrs{
		security.Class:            security.ClassGenericPassword,
		security.AttrService:      service,
		security.ReturnAttributes: true,
		security.MatchLimit:       security.MatchLimitAll,
	})
	if errors.Is(err, security.ErrItemNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list %s in Keychain: %w", service, err)
	}
	items, _ := res.([]any)
	var accounts []string
	for _, it := range items {
		if d, ok := it.(security.Dict); ok {
			if a, ok := d.Get(security.AttrAccount); ok {
				if s, ok := a.(string); ok {
					accounts = append(accounts, s)
				}
			}
		}
	}
	return accounts, nil
}

// ErrWouldPrompt is returned by ReadNoUI for an item macOS would ask the
// user about, such as one another binary wrote.
var ErrWouldPrompt = errors.New("reading it needs a Keychain prompt")

// ReadNoUI is Read with the Keychain prompts of this process turned off.
func ReadNoUI(item Item) ([]byte, error) {
	restore, err := disallowInteraction()
	if err != nil {
		return nil, err
	}
	defer restore()
	data, err := Read(item)
	if errors.Is(err, security.ErrInteractionNotAllowed) {
		return nil, fmt.Errorf("%s: %w", item.Service, ErrWouldPrompt)
	}
	return data, err
}
