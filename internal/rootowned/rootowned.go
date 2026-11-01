// Package rootowned checks that only root can change a file, so a program
// running as the user cannot replace what it says.
package rootowned

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Owners are the owners trusted besides root; tests add the current user.
var Owners []uint32

// Check reports an error unless path and every directory above it, after
// resolving symlinks, are owned by root and writable by no one else.
func Check(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	for p := resolved; ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: unknown owner", p)
		}
		if !trusted(st.Uid) {
			return fmt.Errorf("%s is not owned by root", p)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by users other than its owner", p)
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

func trusted(uid uint32) bool {
	if uid == 0 {
		return true
	}
	for _, o := range Owners {
		if uid == o {
			return true
		}
	}
	return false
}
