package checkdefinition

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	signatureAlgorithm = "Ed25519"
	signatureContext   = "mossward.declarative-check.v1"
)

type signingPayload struct {
	Context string `json:"context"`
	Check   Check  `json:"check"`
}

func Sign(check Check, keyID string, privateKey ed25519.PrivateKey) (SignedCheck, error) {
	if err := Validate(check); err != nil {
		return SignedCheck{}, err
	}
	if !identifierPattern.MatchString(keyID) {
		return SignedCheck{}, errors.New("declarative-check signing key identifier is invalid")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedCheck{}, errors.New("declarative-check signing key is invalid")
	}
	payload, normalized, err := signaturePayload(check)
	if err != nil {
		return SignedCheck{}, err
	}
	return SignedCheck{Algorithm: signatureAlgorithm, KeyID: keyID, Check: normalized,
		Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))}, nil
}

func Verify(envelope SignedCheck, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("declarative-check verification key is invalid")
	}
	payload, _, err := signaturePayload(envelope.Check)
	if err != nil {
		return err
	}
	signature, err := validateEnvelopeMetadata(envelope)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("declarative-check signature verification failed")
	}
	return nil
}

func validateEnvelopeMetadata(envelope SignedCheck) ([]byte, error) {
	if envelope.Algorithm != signatureAlgorithm {
		return nil, errors.New("unsupported declarative-check signature algorithm")
	}
	if !identifierPattern.MatchString(envelope.KeyID) {
		return nil, errors.New("declarative-check signing key identifier is invalid")
	}
	signature, err := base64.RawStdEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("declarative-check signature is invalid")
	}
	return signature, nil
}

func signaturePayload(check Check) ([]byte, Check, error) {
	if err := Validate(check); err != nil {
		return nil, Check{}, err
	}
	canonical, err := canonicalSpec(check.Spec)
	if err != nil {
		return nil, Check{}, err
	}
	check.Spec = canonical
	payload, err := json.Marshal(signingPayload{Context: signatureContext, Check: check})
	if err != nil {
		return nil, Check{}, fmt.Errorf("encode declarative-check signing payload: %w", err)
	}
	return payload, check, nil
}
