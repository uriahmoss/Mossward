package auth

import (
	"errors"
	"testing"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	valid, err := VerifyPassword(hash, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected password to verify")
	}
	valid, err = VerifyPassword(hash, "incorrect password")
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("incorrect password unexpectedly verified")
	}
}

func TestPasswordPolicyRejectsShortPassword(t *testing.T) {
	_, err := HashPassword("too short")
	if !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("expected ErrPasswordTooShort, got %v", err)
	}
}

func TestPasswordVerifierRejectsMalformedHash(t *testing.T) {
	if _, err := VerifyPassword("not-a-password-hash", "password"); err == nil {
		t.Fatal("expected malformed hash to be rejected")
	}
}
