package relaytransport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

const relayKeyContext = "mossward-relay-e2e-v1"

func GenerateEncryptionKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

func EncryptionKeyID(publicKey *ecdh.PublicKey) string {
	digest := sha256.Sum256(publicKey.Bytes())
	return hex.EncodeToString(digest[:16])
}

func Seal(frame Frame, plaintext []byte, signingKey *ecdsa.PrivateKey, recipientKey *ecdh.PublicKey) (Frame, error) {
	if signingKey == nil || recipientKey == nil || len(plaintext) == 0 || len(plaintext) > MaximumCiphertextSize-aes.BlockSize {
		return frame, errors.New("relay encryption input is invalid")
	}
	frame.ProtocolVersion = ProtocolVersion
	frame.RecipientKeyID = EncryptionKeyID(recipientKey)
	ephemeralKey, err := GenerateEncryptionKey()
	if err != nil {
		return frame, err
	}
	frame.EphemeralPublicKey = ephemeralKey.PublicKey().Bytes()
	sharedSecret, err := ephemeralKey.ECDH(recipientKey)
	if err != nil {
		return frame, err
	}
	aead, err := relayAEAD(sharedSecret, frame)
	if err != nil {
		return frame, err
	}
	frame.Nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, frame.Nonce); err != nil {
		return frame, err
	}
	aad, err := authenticatedHeader(frame)
	if err != nil {
		return frame, err
	}
	frame.Ciphertext = aead.Seal(nil, frame.Nonce, plaintext, aad)
	digest := signedDigest(aad, frame.Ciphertext)
	frame.Signature, err = ecdsa.SignASN1(rand.Reader, signingKey, digest)
	if err != nil {
		return frame, err
	}
	return frame, ValidateFrame(frame, time.Now().UTC())
}

func Open(frame Frame, recipientKey *ecdh.PrivateKey, senderKey *ecdsa.PublicKey, now time.Time) ([]byte, error) {
	if recipientKey == nil || senderKey == nil {
		return nil, errors.New("relay decryption keys are required")
	}
	if err := ValidateFrame(frame, now); err != nil {
		return nil, err
	}
	if EncryptionKeyID(recipientKey.PublicKey()) != frame.RecipientKeyID {
		return nil, errors.New("relay message targets a different encryption key")
	}
	aad, err := authenticatedHeader(frame)
	if err != nil {
		return nil, err
	}
	if !ecdsa.VerifyASN1(senderKey, signedDigest(aad, frame.Ciphertext), frame.Signature) {
		return nil, errors.New("relay message signature verification failed")
	}
	ephemeralKey, err := ecdh.X25519().NewPublicKey(frame.EphemeralPublicKey)
	if err != nil {
		return nil, errors.New("relay ephemeral key is invalid")
	}
	sharedSecret, err := recipientKey.ECDH(ephemeralKey)
	if err != nil {
		return nil, err
	}
	aead, err := relayAEAD(sharedSecret, frame)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, frame.Nonce, frame.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("relay message decryption failed")
	}
	return plaintext, nil
}

func relayAEAD(sharedSecret []byte, frame Frame) (cipher.AEAD, error) {
	messageID, err := hex.DecodeString(frame.MessageID)
	if err != nil {
		return nil, err
	}
	reader := hkdf.New(sha256.New, sharedSecret, messageID, []byte(relayKeyContext))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func authenticatedHeader(frame Frame) ([]byte, error) {
	return json.Marshal(struct {
		Context              string      `json:"context"`
		ProtocolVersion      int         `json:"protocol_version"`
		MessageID            string      `json:"message_id"`
		Kind                 MessageKind `json:"kind"`
		DownstreamEndpointID string      `json:"downstream_endpoint_id"`
		SenderID             string      `json:"sender_id"`
		RecipientID          string      `json:"recipient_id"`
		RecipientKeyID       string      `json:"recipient_key_id"`
		Sequence             uint64      `json:"sequence"`
		CreatedAt            time.Time   `json:"created_at"`
		EphemeralPublicKey   []byte      `json:"ephemeral_public_key"`
		Nonce                []byte      `json:"nonce"`
	}{
		Context:              relayKeyContext,
		ProtocolVersion:      frame.ProtocolVersion,
		MessageID:            frame.MessageID,
		Kind:                 frame.Kind,
		DownstreamEndpointID: frame.DownstreamEndpointID,
		SenderID:             frame.SenderID,
		RecipientID:          frame.RecipientID,
		RecipientKeyID:       frame.RecipientKeyID,
		Sequence:             frame.Sequence,
		CreatedAt:            frame.CreatedAt,
		EphemeralPublicKey:   frame.EphemeralPublicKey,
		Nonce:                frame.Nonce,
	})
}

func signedDigest(aad, ciphertext []byte) []byte {
	hash := sha256.New()
	_, _ = hash.Write(aad)
	_, _ = hash.Write(ciphertext)
	return hash.Sum(nil)
}
