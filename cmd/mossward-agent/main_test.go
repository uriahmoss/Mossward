package main

import (
	"strings"
	"testing"
)

func TestReadEnrollmentTokenFromStdin(t *testing.T) {
	token, err := readEnrollmentToken("", true, strings.NewReader("single-use-token\n"))
	if err != nil || token != "single-use-token" {
		t.Fatalf("token = %q, error = %v", token, err)
	}
}

func TestReadEnrollmentTokenRejectsAmbiguousOrOversizedInput(t *testing.T) {
	if _, err := readEnrollmentToken("argument", true, strings.NewReader("stdin")); err == nil {
		t.Fatal("ambiguous token sources were accepted")
	}
	if _, err := readEnrollmentToken("", true, strings.NewReader(strings.Repeat("x", 4097))); err == nil {
		t.Fatal("oversized token input was accepted")
	}
}
