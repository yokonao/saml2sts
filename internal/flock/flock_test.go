package flock

import (
	"testing"
	"time"
)

func TestLockExcludes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	unlock, err := Lock("test.lock")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{})
	go func() {
		u, err := Lock("test.lock")
		if err != nil {
			t.Error(err)
		} else {
			u()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("second Lock did not wait")
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("second Lock did not get the lock after release")
	}
}
