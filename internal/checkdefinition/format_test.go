package checkdefinition

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignVerifyAndRejectTampering(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	check := validCheck()
	envelope, err := Sign(check, "mossward.release-2026", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(envelope, publicKey); err != nil {
		t.Fatalf("verify signed check: %v", err)
	}
	envelope.Check.Severity = "critical"
	if err := Verify(envelope, publicKey); err == nil {
		t.Fatal("tampered declarative check was accepted")
	}
}

func TestSignatureCanonicalizesSpec(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	check := validCheck()
	check.Spec = json.RawMessage(`{ "port": 443, "headers": {"a": "b"} }`)
	envelope, err := Sign(check, "mossward.release-2026", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Check.Spec = json.RawMessage(`{"headers":{"a":"b"},"port":443}`)
	if err := Verify(envelope, publicKey); err != nil {
		t.Fatalf("equivalent JSON changed signature: %v", err)
	}
}

func TestValidateRejectsUnsafeMetadataAndSpec(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Check)
	}{
		{name: "schema", mutate: func(check *Check) { check.SchemaVersion = 2 }},
		{name: "identifier", mutate: func(check *Check) { check.ID = "Shell Command" }},
		{name: "version", mutate: func(check *Check) { check.Version = "latest" }},
		{name: "kind", mutate: func(check *Check) { check.Kind = "script" }},
		{name: "severity", mutate: func(check *Check) { check.Severity = "urgent" }},
		{name: "spec type", mutate: func(check *Check) { check.Spec = json.RawMessage(`[]`) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			check := validCheck()
			test.mutate(&check)
			if err := Validate(check); err == nil {
				t.Fatal("invalid declarative check was accepted")
			}
		})
	}
}

func TestParseSignedRejectsUnknownAndTrailingData(t *testing.T) {
	checkJSON := `{"algorithm":"Ed25519","key_id":"mossward.release-2026","check":{"schema_version":1,"id":"mossward.http.headers","version":"1.0.0","kind":"http","title":"Required headers","severity":"medium","spec":{}},"signature":"value"}`
	for _, document := range []string{
		strings.Replace(checkJSON, `"signature":"value"`, `"unexpected":true,"signature":"value"`, 1),
		checkJSON + `{}`,
	} {
		if _, err := ParseSigned([]byte(document)); err == nil {
			t.Fatal("invalid signed document was accepted")
		}
	}
}

func TestParseSignedAcceptsCompleteEnvelope(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	envelope, err := Sign(validCheck(), "mossward.release-2026", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSigned(document); err != nil {
		t.Fatalf("parse signed check: %v", err)
	}
}

func validCheck() Check {
	return Check{SchemaVersion: SchemaVersion, ID: "mossward.http.headers", Version: "1.0.0", Kind: "http",
		Title: "Required security headers", Description: "Detect missing response headers.", Severity: "medium",
		Spec: json.RawMessage(`{"required_headers":["content-security-policy"]}`)}
}
