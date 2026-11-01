package login

import "testing"

func TestIDPURL(t *testing.T) {
	for _, tt := range []struct{ raw, want string }{
		{"https://idp.example.com/sso?app=aws", "https://idp.example.com/sso?app=aws#saml2sts=N"},
		{"https://idp.example.com/#/apps/aws", "https://idp.example.com/#/apps/aws&saml2sts=N"},
	} {
		got, err := idpURL(tt.raw, "N")
		if err != nil || got != tt.want {
			t.Errorf("idpURL(%q) = %q, %v; want %q", tt.raw, got, err, tt.want)
		}
	}
}
