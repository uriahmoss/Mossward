package checkcatalog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"mossward/internal/checkdefinition"
)

var (
	ErrPublisherNotTrusted = errors.New("declarative-check publisher is not trusted")
	ErrRollbackApproval    = errors.New("declarative-check rollback requires explicit approval")
	ErrVersionNotFound     = errors.New("declarative-check version not found")
	ErrVersionConflict     = errors.New("declarative-check version is immutable")
)

type PublisherStatus string

const (
	PublisherTrusted PublisherStatus = "trusted"
	PublisherRevoked PublisherStatus = "revoked"
)

type CheckStatus string

const (
	CheckStaged  CheckStatus = "staged"
	CheckActive  CheckStatus = "active"
	CheckRetired CheckStatus = "retired"
)

type Publisher struct {
	KeyID     string
	Name      string
	PublicKey ed25519.PublicKey
	Status    PublisherStatus
	AddedAt   time.Time
	RevokedAt *time.Time
}

type Version struct {
	Envelope    checkdefinition.SignedCheck
	Status      CheckStatus
	ImportedAt  time.Time
	ActivatedAt *time.Time
}

type Repository interface {
	SavePublisher(Publisher) error
	Publisher(string) (Publisher, error)
	RevokePublisher(string, time.Time) error
	SaveVersion(Version) error
	Version(string, string) (Version, error)
	ActiveVersion(string) (Version, error)
	ActivateVersion(string, string, time.Time) error
}

type Service struct{ repository Repository }

func New(repository Repository) *Service { return &Service{repository: repository} }

func (s *Service) TrustPublisher(keyID, name string, publicKey ed25519.PublicKey, now time.Time) error {
	if strings.TrimSpace(name) == "" || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("declarative-check publisher name and Ed25519 public key are required")
	}
	if existing, err := s.repository.Publisher(keyID); err == nil && !bytes.Equal(existing.PublicKey, publicKey) {
		return errors.New("declarative-check publisher key identifier is already bound to another key")
	}
	return s.repository.SavePublisher(Publisher{KeyID: keyID, Name: strings.TrimSpace(name),
		PublicKey: append(ed25519.PublicKey(nil), publicKey...), Status: PublisherTrusted, AddedAt: now.UTC()})
}

func (s *Service) RevokePublisher(keyID string, now time.Time) error {
	return s.repository.RevokePublisher(keyID, now.UTC())
}

func (s *Service) Import(envelope checkdefinition.SignedCheck, now time.Time) error {
	publisher, err := s.repository.Publisher(envelope.KeyID)
	if err != nil || publisher.Status != PublisherTrusted {
		return ErrPublisherNotTrusted
	}
	if err := checkdefinition.Verify(envelope, publisher.PublicKey); err != nil {
		return fmt.Errorf("verify declarative check: %w", err)
	}
	if existing, err := s.repository.Version(envelope.Check.ID, envelope.Check.Version); err == nil {
		if existing.Envelope.Signature == envelope.Signature && existing.Envelope.KeyID == envelope.KeyID {
			return nil
		}
		return ErrVersionConflict
	}
	return s.repository.SaveVersion(Version{Envelope: envelope, Status: CheckStaged, ImportedAt: now.UTC()})
}

func (s *Service) Activate(checkID, version string, allowRollback bool, now time.Time) error {
	candidate, err := s.repository.Version(checkID, version)
	if err != nil {
		return ErrVersionNotFound
	}
	publisher, err := s.repository.Publisher(candidate.Envelope.KeyID)
	if err != nil || publisher.Status != PublisherTrusted {
		return ErrPublisherNotTrusted
	}
	active, err := s.repository.ActiveVersion(checkID)
	if err == nil && compareVersions(version, active.Envelope.Check.Version) < 0 && !allowRollback {
		return ErrRollbackApproval
	}
	return s.repository.ActivateVersion(checkID, version, now.UTC())
}

func compareVersions(left, right string) int {
	lCore, lPre := splitVersion(left)
	rCore, rPre := splitVersion(right)
	for index := range lCore {
		if lCore[index] < rCore[index] {
			return -1
		}
		if lCore[index] > rCore[index] {
			return 1
		}
	}
	if lPre == rPre {
		return 0
	}
	if lPre == "" {
		return 1
	}
	if rPre == "" {
		return -1
	}
	return comparePrerelease(lPre, rPre)
}

func splitVersion(value string) ([3]int, string) {
	value = strings.SplitN(value, "+", 2)[0]
	parts := strings.SplitN(value, "-", 2)
	coreParts := strings.Split(parts[0], ".")
	var core [3]int
	for index := range core {
		core[index], _ = strconv.Atoi(coreParts[index])
	}
	if len(parts) == 2 {
		return core, parts[1]
	}
	return core, ""
}

func comparePrerelease(left, right string) int {
	lParts, rParts := strings.Split(left, "."), strings.Split(right, ".")
	for index := 0; index < len(lParts) && index < len(rParts); index++ {
		if lParts[index] == rParts[index] {
			continue
		}
		lNumber, lErr := strconv.Atoi(lParts[index])
		rNumber, rErr := strconv.Atoi(rParts[index])
		if lErr == nil && rErr == nil {
			if lNumber < rNumber {
				return -1
			}
			return 1
		}
		if lErr == nil {
			return -1
		}
		if rErr == nil {
			return 1
		}
		if lParts[index] < rParts[index] {
			return -1
		}
		return 1
	}
	if len(lParts) < len(rParts) {
		return -1
	}
	if len(lParts) > len(rParts) {
		return 1
	}
	return 0
}
