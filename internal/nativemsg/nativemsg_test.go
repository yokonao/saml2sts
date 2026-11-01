package nativemsg

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := map[string]string{"samlResponse": "PHNhbWw+"}
	if err := Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := Read(&buf, &out); err != nil {
		t.Fatal(err)
	}
	if out["samlResponse"] != in["samlResponse"] {
		t.Fatalf("got %v, want %v", out, in)
	}
}

func TestWriteTooLarge(t *testing.T) {
	if err := Write(&bytes.Buffer{}, string(make([]byte, maxWrite))); err == nil {
		t.Fatal("expected error")
	}
}
