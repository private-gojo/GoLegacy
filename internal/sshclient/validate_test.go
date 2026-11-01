package sshclient

import (
	"testing"

	"dev.go.core/internal/profile"
)

func TestValidateProfileRejectsMalformedPrivateKey(t *testing.T) {
	p := profile.Profile{Mode: profile.ModeDirect, Host: "127.0.0.1", Port: 22, Username: "u", PrivateKey: "not-a-private-key"}
	if err := ValidateProfile(p); err == nil { t.Fatal("malformed private key was accepted") }
}
