package relaytransport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func TestSealOpenProvidesEndToEndConfidentialityAndAuthenticity(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientKey, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	frame := Frame{MessageID: "00112233445566778899aabbccddeeff", Kind: MessageTamperAlert, DownstreamEndpointID: "endpoint",
		SenderID: "endpoint", RecipientID: "server", Sequence: 1, CreatedAt: now}
	sealed, err := Seal(frame, []byte("tamper evidence"), signingKey, recipientKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := Open(sealed, recipientKey, &signingKey.PublicKey, now)
	if err != nil || string(plaintext) != "tamper evidence" {
		t.Fatalf("opened plaintext = %q, error = %v", plaintext, err)
	}
	otherRecipient, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(sealed, otherRecipient, &signingKey.PublicKey, now); err == nil {
		t.Fatal("unintended recipient decrypted relay message")
	}
	sealed.Ciphertext[0] ^= 1
	if _, err := Open(sealed, recipientKey, &signingKey.PublicKey, now); err == nil {
		t.Fatal("altered relay message was accepted")
	}
}
