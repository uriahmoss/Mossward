package checkdefinition

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	SchemaVersion = 1
	maxSpecBytes  = 64 * 1024
	maxTitleBytes = 160
)

var (
	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$`)
	versionPattern    = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	validKinds        = map[string]bool{"http": true, "ssh": true, "tls": true}
	validSeverities   = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
)

type Check struct {
	SchemaVersion int             `json:"schema_version"`
	ID            string          `json:"id"`
	Version       string          `json:"version"`
	Kind          string          `json:"kind"`
	Title         string          `json:"title"`
	Description   string          `json:"description,omitempty"`
	Severity      string          `json:"severity"`
	Spec          json.RawMessage `json:"spec"`
}

type SignedCheck struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Check     Check  `json:"check"`
	Signature string `json:"signature"`
}

func ParseSigned(data []byte) (SignedCheck, error) {
	var envelope SignedCheck
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return SignedCheck{}, fmt.Errorf("decode signed check: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return SignedCheck{}, err
	}
	if err := Validate(envelope.Check); err != nil {
		return SignedCheck{}, err
	}
	if _, err := validateEnvelopeMetadata(envelope); err != nil {
		return SignedCheck{}, err
	}
	return envelope, nil
}

func Validate(check Check) error {
	if check.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported declarative-check schema version %d", check.SchemaVersion)
	}
	if !identifierPattern.MatchString(check.ID) {
		return errors.New("declarative-check identifier must be namespaced and use lowercase letters, numbers, dots, underscores, or hyphens")
	}
	if !versionPattern.MatchString(check.Version) {
		return errors.New("declarative-check version must use semantic versioning")
	}
	if !validKinds[check.Kind] {
		return errors.New("declarative-check kind is unsupported")
	}
	if !validSeverities[check.Severity] {
		return errors.New("declarative-check severity is unsupported")
	}
	title := strings.TrimSpace(check.Title)
	if title == "" || len(title) > maxTitleBytes {
		return fmt.Errorf("declarative-check title must contain 1 to %d bytes", maxTitleBytes)
	}
	if len(check.Spec) == 0 || len(check.Spec) > maxSpecBytes {
		return fmt.Errorf("declarative-check spec must contain 1 to %d bytes", maxSpecBytes)
	}
	canonical, err := canonicalSpec(check.Spec)
	if err != nil {
		return err
	}
	if len(canonical) == 0 || canonical[0] != '{' {
		return errors.New("declarative-check spec must be a JSON object")
	}
	return nil
}

func canonicalSpec(spec json.RawMessage) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(spec))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode declarative-check spec: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonicalize declarative-check spec: %w", err)
	}
	return canonical, nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("declarative-check document must contain one JSON value")
	}
	return nil
}
