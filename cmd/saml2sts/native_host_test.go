package main

import "testing"

func TestStartedByBrowser(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want bool
	}{
		{[]string{"chrome-extension://ljanpcedhfnidohflcgdjflhhjebpikb/"}, true},
		{[]string{"/Users/a/Library/Application Support/Mozilla/NativeMessagingHosts/io.github.yokonao.saml2sts.json", "saml2sts@yokonao.github.io"}, true},
		{[]string{"login", "-p", "poc"}, false},
		{[]string{"exec", "-p", "poc", "--", "cat", "/tmp/a.json"}, false},
		{nil, false},
	} {
		if got := startedByBrowser(tt.args); got != tt.want {
			t.Errorf("startedByBrowser(%q) = %v, want %v", tt.args, got, tt.want)
		}
	}
}
