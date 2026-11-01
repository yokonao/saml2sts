package rootowned

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheck(t *testing.T) {
	if err := Check("/usr/bin/true"); err != nil {
		t.Errorf("Check(/usr/bin/true) = %v", err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Check(file); err == nil {
		t.Error("Check accepted a file the user owns")
	}

	Owners = []uint32{uint32(os.Getuid())}
	t.Cleanup(func() { Owners = nil })
	if err := Check(file); err != nil {
		t.Errorf("Check with the user trusted = %v", err)
	}
	if err := os.Chmod(file, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := Check(file); err == nil {
		t.Error("Check accepted a world-writable file")
	}
}
