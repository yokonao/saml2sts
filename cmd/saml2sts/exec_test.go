package main

import (
	"strings"
	"testing"
	"time"

	"github.com/yokonao/saml2sts/internal/federation"
)

func TestExecEnv(t *testing.T) {
	parent := []string{
		"PATH=/usr/bin",
		"AWS_ACCESS_KEY_ID=parent",
		"AWS_SECRET_ACCESS_KEY=parent",
		"AWS_SESSION_TOKEN=parent",
		"AWS_SECURITY_TOKEN=parent",
		"AWS_CREDENTIAL_EXPIRATION=parent",
		"SAML2STS_ROLE=parent",
		"AWS_PROFILE=parent",
		"AWS_REGION=us-east-1",
	}
	c := federation.Credentials{AccessKeyID: "id", SecretAccessKey: "secret", SessionToken: "token",
		Expiration: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	got := map[string][]string{}
	for _, kv := range execEnv(parent, c, "arn:aws:iam::111111111111:role/admin") {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = append(got[k], v)
	}
	for k, want := range map[string]string{
		"AWS_ACCESS_KEY_ID":         "id",
		"AWS_SECRET_ACCESS_KEY":     "secret",
		"AWS_SESSION_TOKEN":         "token",
		"AWS_CREDENTIAL_EXPIRATION": "2026-01-02T03:04:05Z",
		"SAML2STS_ROLE":             "arn:aws:iam::111111111111:role/admin",
		"PATH":                      "/usr/bin",
		"AWS_REGION":                "us-east-1",
	} {
		if len(got[k]) != 1 || got[k][0] != want {
			t.Errorf("%s = %q, want exactly %q", k, got[k], want)
		}
	}
	for _, k := range []string{"AWS_SECURITY_TOKEN", "AWS_PROFILE"} {
		if v, ok := got[k]; ok {
			t.Errorf("%s inherited: %q", k, v)
		}
	}
}
