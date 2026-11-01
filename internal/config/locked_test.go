package config

import (
	"strings"
	"testing"
	"time"

	"dev.go.core/internal/profile"
)

func TestLockedURIEncryptedRoundTrip(t *testing.T) {
	cfg := LockedConfig{
		Profile: profile.Profile{Mode:profile.ModeDirect,Host:"ssh.example.test",Port:22,Username:"user",Password:"secret"},
		ExpiryUnixMilli:0,Message:"locked payload",BlockRoot:true,
	}
	uri,err:=EncodeLockedURI(cfg,"test-passcode")
	if err!=nil{t.Fatal(err)}
	if !strings.HasPrefix(uri,"go-ssh://locked/"){t.Fatalf("unexpected URI %q",uri)}
	got,err:=DecodeLockedURI(uri,"test-passcode",time.UnixMilli(100))
	if err!=nil{t.Fatal(err)}
	if !got.Locked||got.Profile.Password!="secret"||got.Message!="locked payload"||!got.BlockRoot{t.Fatalf("unexpected decoded config: %+v",got)}
}

func TestLockedURIDoesNotAcceptWrongPasscode(t *testing.T) {
	cfg:=LockedConfig{Profile:profile.Profile{Mode:profile.ModeDirect,Host:"ssh.example.test",Port:22,Username:"user"}}
	uri,err:=EncodeLockedURI(cfg,"correctpass")
	if err!=nil{t.Fatal(err)}
	if _,err=DecodeLockedURI(uri,"wrongpass",time.Now());err==nil{t.Fatal("wrong passcode accepted")}
}

func TestLockedURIExpiry(t *testing.T) {
	cfg:=LockedConfig{Profile:profile.Profile{Mode:profile.ModeDirect,Host:"ssh.example.test",Port:22,Username:"user"},ExpiryUnixMilli:1000}
	uri,err:=EncodeLockedURI(cfg,"")
	if err!=nil{t.Fatal(err)}
	if _,err=DecodeLockedURI(uri,"",time.UnixMilli(1000));err==nil{t.Fatal("expired profile accepted")}
}

func TestLockedURIPlaintextMode(t *testing.T) {
	cfg:=LockedConfig{Profile:profile.Profile{Mode:profile.ModeDirect,Host:"ssh.example.test",Port:22,Username:"user"}}
	uri,err:=EncodeLockedURI(cfg,"")
	if err!=nil{t.Fatal(err)}
	got,err:=DecodeLockedURI(uri,"",time.Now())
	if err!=nil||!got.Locked{t.Fatalf("got=%+v err=%v",got,err)}
}

func TestLockedURIRejectsNegativeExpiry(t *testing.T) {
	cfg := LockedConfig{
		Profile: profile.Profile{Mode: profile.ModeDirect, Host: "ssh.example.test", Port: 22, Username: "user"},
		ExpiryUnixMilli: -1,
	}
	if _, err := EncodeLockedURI(cfg, ""); err == nil {
		t.Fatal("negative expiry accepted")
	}
}

func TestLockedURIPasscodeLengthUsesCharacters(t *testing.T) {
	cfg := LockedConfig{
		Profile: profile.Profile{Mode: profile.ModeDirect, Host: "ssh.example.test", Port: 22, Username: "user"},
	}
	if _, err := EncodeLockedURI(cfg, "éééé"); err == nil {
		t.Fatal("four Unicode characters should not satisfy the eight-character minimum")
	}
}
