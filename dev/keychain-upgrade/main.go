//go:build darwin

// Command keychain-upgrade writes or reads a Keychain item the way saml2sts
// does, so dev/keychain-upgrade.sh can check which signatures keep access
// when the binary is replaced.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/yokonao/saml2sts/internal/keychain"
)

// build differs between the two binaries the script compares.
var build = "1"

var item = keychain.Item{Service: "saml2sts.upgrade-test", Account: "test"}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: keychain-upgrade write|read|delete")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "write":
		err = keychain.Write(item, []byte("written by build "+build))
	case "read":
		var b []byte
		b, err = keychain.ReadNoUI(item)
		if err == nil && b == nil {
			err = errors.New("item not found")
		}
		if err == nil {
			fmt.Printf("build %s read %q\n", build, b)
		}
	case "delete":
		err = keychain.Delete(item)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if errors.Is(err, keychain.ErrWouldPrompt) {
		fmt.Printf("build %s: %v\n", build, err)
		os.Exit(3)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
