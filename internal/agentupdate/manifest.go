package agentupdate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"time"
)

const (
	manifestSchemaVersion = 1
	maximumManifestBytes  = 64 << 10
	maximumArtifactBytes  = 256 << 20
	maximumManifestLife   = 30 * 24 * time.Hour
	maximumClockSkew      = 5 * time.Minute
	minimumHealthTimeout  = 30
	maximumHealthTimeout  = 600
)

var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)

type Envelope struct {
	KeyID     string `json:"key_id"`
	Manifest  string `json:"manifest"`
	Signature string `json:"signature"`
}

type Manifest struct {
	SchemaVersion        int       `json:"schema_version"`
	Version              string    `json:"version"`
	OperatingSystem      string    `json:"operating_system"`
	Architecture         string    `json:"architecture"`
	ArtifactURL          string    `json:"artifact_url"`
	ArtifactSHA256       string    `json:"artifact_sha256"`
	ArtifactSize         int64     `json:"artifact_size"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	HealthTimeoutSeconds int       `json:"health_timeout_seconds"`
}

func Verify(reader io.Reader, trustedKey ed25519.PublicKey, expectedKeyID string, now time.Time) (Manifest, error) {
	var envelope Envelope
	decoder := json.NewDecoder(io.LimitReader(reader, maximumManifestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Manifest{}, fmt.Errorf("decode update envelope: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Manifest{}, errors.New("update envelope contains trailing data")
	}
	if envelope.KeyID == "" || envelope.KeyID != expectedKeyID {
		return Manifest{}, errors.New("update envelope uses an untrusted signing key")
	}
	manifestBytes, err := base64.RawStdEncoding.DecodeString(envelope.Manifest)
	if err != nil {
		return Manifest{}, errors.New("update manifest encoding is invalid")
	}
	signature, err := base64.RawStdEncoding.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(trustedKey, signingPayload(envelope.KeyID, manifestBytes), signature) {
		return Manifest{}, errors.New("update manifest signature is invalid")
	}
	manifest, err := decodeManifest(manifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	return manifest, manifest.Validate(now)
}

func signingPayload(keyID string, manifest []byte) []byte {
	payload := make([]byte, 0, len(keyID)+1+len(manifest))
	payload = append(payload, keyID...)
	payload = append(payload, 0)
	return append(payload, manifest...)
}

func decodeManifest(data []byte) (Manifest, error) {
	var manifest Manifest
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(data), maximumManifestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode signed update manifest: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Manifest{}, errors.New("signed update manifest contains trailing data")
	}
	return manifest, nil
}

func (m Manifest) Validate(now time.Time) error {
	if m.SchemaVersion != manifestSchemaVersion || !versionPattern.MatchString(m.Version) {
		return errors.New("update manifest schema or version is invalid")
	}
	if (m.OperatingSystem != "linux" && m.OperatingSystem != "windows") || (m.Architecture != "amd64" && m.Architecture != "arm64") {
		return errors.New("update manifest platform is unsupported")
	}
	parsedURL, err := url.Parse(m.ArtifactURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.Fragment != "" {
		return errors.New("update artifact URL must be HTTPS without credentials or fragments")
	}
	digest, err := hex.DecodeString(m.ArtifactSHA256)
	if err != nil || len(digest) != 32 {
		return errors.New("update artifact SHA-256 is invalid")
	}
	if m.ArtifactSize < 1 || m.ArtifactSize > maximumArtifactBytes {
		return errors.New("update artifact size is outside the permitted range")
	}
	if m.IssuedAt.After(now.Add(maximumClockSkew)) || !m.ExpiresAt.After(now) || !m.ExpiresAt.After(m.IssuedAt) || m.ExpiresAt.Sub(m.IssuedAt) > maximumManifestLife {
		return errors.New("update manifest validity window is invalid")
	}
	if m.HealthTimeoutSeconds < minimumHealthTimeout || m.HealthTimeoutSeconds > maximumHealthTimeout {
		return errors.New("update health timeout is outside the permitted range")
	}
	return nil
}
