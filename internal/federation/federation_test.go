package federation

import (
	"testing"
	"time"
)

func TestFresh(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		lifetime time.Duration
		left     time.Duration
		want     bool
	}{
		{"long session, plenty left", time.Hour, 30 * time.Minute, true},
		{"long session, inside margin", time.Hour, 10 * time.Minute, false},
		{"15m session, just issued", 15 * time.Minute, 14 * time.Minute, true},
		{"15m session, past half", 15 * time.Minute, 7 * time.Minute, false},
	}
	for _, tt := range tests {
		exp := now.Add(tt.left)
		c := Credentials{AccessKeyID: "AKIA", Expiration: exp, Issued: exp.Add(-tt.lifetime)}
		if got := c.Fresh(16 * time.Minute); got != tt.want {
			t.Errorf("%s: Fresh = %v, want %v", tt.name, got, tt.want)
		}
	}
}
