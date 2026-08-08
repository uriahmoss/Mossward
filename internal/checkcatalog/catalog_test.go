package checkcatalog

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"mossward/internal/checkdefinition"
)

func TestLifecycleRequiresTrustAndExplicitRollback(t *testing.T) {
	now := time.Now().UTC()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	repository := newMemoryRepository()
	service := New(repository)
	one := signedVersion(t, privateKey, "1.0.0")
	if err := service.Import(one, now); !errors.Is(err, ErrPublisherNotTrusted) {
		t.Fatalf("untrusted import error = %v", err)
	}
	if err := service.TrustPublisher(one.KeyID, "Mossward releases", publicKey, now); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.0.0", "2.0.0"} {
		if err := service.Import(signedVersion(t, privateKey, version), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.Activate(one.Check.ID, "2.0.0", false, now); err != nil {
		t.Fatal(err)
	}
	if err := service.Activate(one.Check.ID, "1.0.0", false, now); !errors.Is(err, ErrRollbackApproval) {
		t.Fatalf("rollback error = %v", err)
	}
	if err := service.Activate(one.Check.ID, "1.0.0", true, now); err != nil {
		t.Fatal(err)
	}
	active, _ := repository.ActiveVersion(one.Check.ID)
	if active.Envelope.Check.Version != "1.0.0" {
		t.Fatalf("active version = %s", active.Envelope.Check.Version)
	}
}

func TestRevokedPublisherBlocksActivation(t *testing.T) {
	now := time.Now().UTC()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	repository := newMemoryRepository()
	service := New(repository)
	envelope := signedVersion(t, privateKey, "1.0.0")
	if err := service.TrustPublisher(envelope.KeyID, "Publisher", publicKey, now); err != nil {
		t.Fatal(err)
	}
	if err := service.Import(envelope, now); err != nil {
		t.Fatal(err)
	}
	if err := service.RevokePublisher(envelope.KeyID, now); err != nil {
		t.Fatal(err)
	}
	if err := service.Activate(envelope.Check.ID, "1.0.0", false, now); !errors.Is(err, ErrPublisherNotTrusted) {
		t.Fatalf("revoked activation error = %v", err)
	}
}

func TestImportRejectsTamperedCheck(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	repository := newMemoryRepository()
	service := New(repository)
	envelope := signedVersion(t, privateKey, "1.0.0")
	_ = service.TrustPublisher(envelope.KeyID, "Publisher", publicKey, time.Now())
	envelope.Check.Title = "Tampered"
	if err := service.Import(envelope, time.Now()); err == nil {
		t.Fatal("tampered check imported")
	}
}

func signedVersion(t *testing.T, privateKey ed25519.PrivateKey, version string) checkdefinition.SignedCheck {
	t.Helper()
	check := checkdefinition.Check{SchemaVersion: 1, ID: "mossward.http.lifecycle", Version: version, Kind: "http",
		Title: "Lifecycle", Severity: "low", Spec: json.RawMessage(`{"require_https":true,"remediation":"Use HTTPS."}`)}
	envelope, err := checkdefinition.Sign(check, "mossward.release-2026", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

type memoryRepository struct {
	publishers map[string]Publisher
	versions   map[string]Version
	active     map[string]string
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{publishers: make(map[string]Publisher), versions: make(map[string]Version), active: make(map[string]string)}
}
func (r *memoryRepository) SavePublisher(value Publisher) error {
	r.publishers[value.KeyID] = value
	return nil
}
func (r *memoryRepository) Publisher(id string) (Publisher, error) {
	value, ok := r.publishers[id]
	if !ok {
		return Publisher{}, errors.New("not found")
	}
	return value, nil
}
func (r *memoryRepository) RevokePublisher(id string, at time.Time) error {
	value, ok := r.publishers[id]
	if !ok {
		return errors.New("not found")
	}
	value.Status = PublisherRevoked
	value.RevokedAt = &at
	r.publishers[id] = value
	return nil
}
func (r *memoryRepository) SaveVersion(value Version) error {
	r.versions[value.Envelope.Check.ID+"@"+value.Envelope.Check.Version] = value
	return nil
}
func (r *memoryRepository) Version(id, version string) (Version, error) {
	value, ok := r.versions[id+"@"+version]
	if !ok {
		return Version{}, errors.New("not found")
	}
	return value, nil
}
func (r *memoryRepository) ActiveVersion(id string) (Version, error) {
	version, ok := r.active[id]
	if !ok {
		return Version{}, errors.New("not found")
	}
	return r.Version(id, version)
}
func (r *memoryRepository) ActivateVersion(id, version string, at time.Time) error {
	if current := r.active[id]; current != "" {
		value, _ := r.Version(id, current)
		value.Status = CheckRetired
		r.versions[id+"@"+current] = value
	}
	value, err := r.Version(id, version)
	if err != nil {
		return err
	}
	value.Status = CheckActive
	value.ActivatedAt = &at
	r.versions[id+"@"+version] = value
	r.active[id] = version
	return nil
}
