package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"mossward/internal/checkcatalog"
	"mossward/internal/checkdefinition"
)

func TestCheckCatalogPersistsTrustAndActivation(t *testing.T) {
	repository := openTestStore(t)
	service := checkcatalog.New(repository)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Microsecond)
	check := checkdefinition.Check{SchemaVersion: 1, ID: "mossward.http.persisted", Version: "1.0.0", Kind: "http",
		Title: "Persisted", Severity: "low", Spec: json.RawMessage(`{"require_https":true,"remediation":"Use HTTPS."}`)}
	envelope, err := checkdefinition.Sign(check, "mossward.release-2026", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.TrustPublisher(envelope.KeyID, "Mossward", publicKey, now); err != nil {
		t.Fatal(err)
	}
	if err := service.Import(envelope, now); err != nil {
		t.Fatal(err)
	}
	if err := service.Activate(check.ID, check.Version, false, now); err != nil {
		t.Fatal(err)
	}
	active, err := repository.ActiveVersion(check.ID)
	if err != nil || active.Status != checkcatalog.CheckActive || active.Envelope.Check.Version != check.Version {
		t.Fatalf("unexpected active check: %#v, %v", active, err)
	}
}
