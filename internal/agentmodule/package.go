package agentmodule

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type Envelope struct {
	Manifest  json.RawMessage `json:"manifest"`
	Package   string          `json:"package"`
	Signature string          `json:"signature"`
}

func Verify(reader io.Reader, publicKey ed25519.PublicKey, expectedKeyID string) (Manifest, []byte, error) {
	var envelope Envelope
	decoder := json.NewDecoder(io.LimitReader(reader, MaximumPackageBytes*2))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Manifest{}, nil, errors.New("module envelope is invalid")
	}
	var manifest Manifest
	manifestDecoder := json.NewDecoder(bytes.NewReader(envelope.Manifest))
	manifestDecoder.DisallowUnknownFields()
	if err := manifestDecoder.Decode(&manifest); err != nil || manifestDecoder.Decode(&struct{}{}) != io.EOF {
		return Manifest{}, nil, errors.New("module manifest is invalid")
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, nil, err
	}
	if manifest.PublisherKeyID != expectedKeyID || len(publicKey) != ed25519.PublicKeySize {
		return Manifest{}, nil, errors.New("module publisher is not trusted")
	}
	pkg, err := base64.RawStdEncoding.DecodeString(envelope.Package)
	if err != nil || int64(len(pkg)) != manifest.PackageSize {
		return Manifest{}, nil, errors.New("module package size is invalid")
	}
	digest := sha256.Sum256(pkg)
	if hex.EncodeToString(digest[:]) != manifest.PackageSHA256 {
		return Manifest{}, nil, errors.New("module package checksum mismatch")
	}
	signature, err := base64.RawStdEncoding.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(publicKey, signedPayload(envelope.Manifest, digest[:]), signature) {
		return Manifest{}, nil, errors.New("module signature is invalid")
	}
	return manifest, pkg, nil
}

func Sign(manifest Manifest, pkg []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	digest := sha256.Sum256(pkg)
	manifest.PackageSHA256, manifest.PackageSize = hex.EncodeToString(digest[:]), int64(len(pkg))
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode module manifest: %w", err)
	}
	envelope := Envelope{Manifest: manifestJSON, Package: base64.RawStdEncoding.EncodeToString(pkg),
		Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, signedPayload(manifestJSON, digest[:])))}
	return json.Marshal(envelope)
}

func signedPayload(manifest, digest []byte) []byte {
	payload := make([]byte, 0, len(manifest)+1+len(digest))
	payload = append(payload, manifest...)
	payload = append(payload, 0)
	return append(payload, digest...)
}
