package store

import (
	"testing"
	"time"
)

func TestPendingAccepts(t *testing.T) {
	now := time.Now()
	p := &Pending{Nonce: "N", Expires: now.Add(time.Minute)}
	for _, tt := range []struct {
		name  string
		p     *Pending
		nonce string
		want  bool
	}{
		{"matching nonce", p, "N", true},
		{"wrong nonce", p, "M", false},
		{"missing nonce", p, "", false},
		{"pending without a nonce", &Pending{Expires: now.Add(time.Minute)}, "", false},
		{"expired", &Pending{Nonce: "N", Expires: now.Add(-time.Second)}, "N", false},
		{"no pending login", nil, "N", false},
	} {
		if got := tt.p.Accepts(tt.nonce, now); got != tt.want {
			t.Errorf("%s: Accepts = %v, want %v", tt.name, got, tt.want)
		}
	}
}
