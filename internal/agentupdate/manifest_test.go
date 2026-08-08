package agentupdate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestVerifyAcceptsValidSignedManifest(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifest(now)
	envelope := signedEnvelope(t, manifest, "release-2026", privateKey)
	verified, err := Verify(bytes.NewReader(envelope), publicKey, "release-2026", now)
	if err != nil || verified.Version != manifest.Version {
		t.Fatalf("verified manifest = %#v, error = %v", verified, err)
	}
}

func TestVerifyRejectsTamperingAndUntrustedKeys(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope := signedEnvelope(t, validManifest(now), "release-2026", privateKey)
	if _, err := Verify(bytes.NewReader(envelope), publicKey, "different-key", now); err == nil {
		t.Fatal("untrusted key identifier was accepted")
	}
	tampered := bytes.Replace(envelope, []byte("release-2026"), []byte("release-2027"), 1)
	if _, err := Verify(bytes.NewReader(tampered), publicKey, "release-2027", now); err == nil {
		t.Fatal("tampered envelope was accepted")
	}
}

func TestManifestRejectsUnsafeArtifactAndValidityWindow(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	manifest := validManifest(now)
	manifest.ArtifactURL = "http://updates.example.test/agent"
	if err := manifest.Validate(now); err == nil {
		t.Fatal("insecure artifact URL was accepted")
	}
	manifest = validManifest(now)
	manifest.ExpiresAt = now.Add(31 * 24 * time.Hour)
	if err := manifest.Validate(now); err == nil {
		t.Fatal("overlong update validity was accepted")
	}
}

func TestVerifyRejectsUnknownManifestFields(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(validManifest(now))
	manifest = []byte(strings.TrimSuffix(string(manifest), "}") + `,"command":"whoami"}`)
	signature := ed25519.Sign(privateKey, signingPayload("release", manifest))
	envelope, _ := json.Marshal(Envelope{KeyID: "release", Manifest: base64.RawStdEncoding.EncodeToString(manifest), Signature: base64.RawStdEncoding.EncodeToString(signature)})
	if _, err := Verify(bytes.NewReader(envelope), publicKey, "release", now); err == nil {
		t.Fatal("unknown manifest field was accepted")
	}
}

func validManifest(now time.Time) Manifest {
	return Manifest{SchemaVersion: 1, Version: "1.2.3", OperatingSystem: "linux", Architecture: "amd64",
		ArtifactURL: "https://updates.example.test/mossward-agent", ArtifactSHA256: strings.Repeat("a", 64),
		ArtifactSize: 1024, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), HealthTimeoutSeconds: 60}
}

func signedEnvelope(t *testing.T, manifest Manifest, keyID string, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(Envelope{KeyID: keyID, Manifest: base64.RawStdEncoding.EncodeToString(payload),
		Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, signingPayload(keyID, payload)))})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
