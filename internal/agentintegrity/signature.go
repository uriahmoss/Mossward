package agentintegrity

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"mossward/internal/model"
)

const signatureContext = "mossward-agent-integrity-v1"

func Sign(key *ecdsa.PrivateKey, sequence uint64, snapshot model.AgentIntegritySnapshot) (model.SignedAgentIntegritySnapshot, error) {
	envelope := model.SignedAgentIntegritySnapshot{Sequence: sequence, Snapshot: snapshot}
	payload, err := canonical(envelope)
	if err != nil {
		return envelope, err
	}
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return envelope, err
	}
	envelope.Signature = base64.RawStdEncoding.EncodeToString(signature)
	return envelope, nil
}

func Verify(publicKey *ecdsa.PublicKey, envelope model.SignedAgentIntegritySnapshot) error {
	if envelope.Sequence == 0 || envelope.Signature == "" {
		return errors.New("integrity sequence and signature are required")
	}
	signature, err := base64.RawStdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return errors.New("integrity signature is invalid")
	}
	payload, err := canonical(envelope)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return errors.New("integrity signature verification failed")
	}
	return nil
}

func canonical(envelope model.SignedAgentIntegritySnapshot) ([]byte, error) {
	return json.Marshal(struct {
		Context  string                       `json:"context"`
		Sequence uint64                       `json:"sequence"`
		Snapshot model.AgentIntegritySnapshot `json:"snapshot"`
	}{Context: signatureContext, Sequence: envelope.Sequence, Snapshot: envelope.Snapshot})
}
