package keychain

import (
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
)

var (
	loadInteraction sync.Once
	setInteraction  func(allowed bool) int32
	getInteraction  func(allowed *bool) int32
	errInteraction  error
)

// disallowInteraction turns off the prompts of the file-based login
// Keychain for this process, which SecItem queries cannot do themselves.
func disallowInteraction() (restore func(), err error) {
	loadInteraction.Do(func() {
		lib, err := purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
		if err != nil {
			errInteraction = err
			return
		}
		purego.RegisterLibFunc(&setInteraction, lib, "SecKeychainSetUserInteractionAllowed")
		purego.RegisterLibFunc(&getInteraction, lib, "SecKeychainGetUserInteractionAllowed")
	})
	if errInteraction != nil {
		return nil, errInteraction
	}
	var was bool
	if st := getInteraction(&was); st != 0 {
		return nil, fmt.Errorf("SecKeychainGetUserInteractionAllowed: %d", st)
	}
	if st := setInteraction(false); st != 0 {
		return nil, fmt.Errorf("SecKeychainSetUserInteractionAllowed: %d", st)
	}
	return func() { _ = setInteraction(was) }, nil
}
