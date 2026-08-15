package agentintegrity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestSignVerifyBindsSequenceAndSnapshot(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := model.AgentIntegritySnapshot{ExecutableSHA256: "a", ConfigurationSHA256: "b", IdentitySHA256: "c", ObservedAt: time.Now().UTC()}
	envelope, err := Sign(key, 1, snapshot)
	if err != nil || Verify(&key.PublicKey, envelope) != nil {
		t.Fatalf("signed envelope = %#v, error = %v", envelope, err)
	}
	envelope.Sequence++
	if Verify(&key.PublicKey, envelope) == nil {
		t.Fatal("signature accepted after sequence alteration")
	}
}
