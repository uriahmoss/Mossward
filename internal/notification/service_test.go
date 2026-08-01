package notification

import (
	"mossward/internal/auth"
	"mossward/internal/model"
	"path/filepath"
	"testing"
)

type memoryStore struct {
	settings model.SMTPSettings
	users    []model.User
}

func (s *memoryStore) SMTPSettings() (model.SMTPSettings, error) { return s.settings, nil }
func (s *memoryStore) SaveSMTPSettings(value model.SMTPSettings, _ model.AuditEvent) error {
	s.settings = value
	return nil
}
func (s *memoryStore) ListUsers() ([]model.User, error) { return s.users, nil }
func TestSMTPPasswordIsEncrypted(t *testing.T) {
	box, err := auth.LoadOrCreateSecretBox(filepath.Join(t.TempDir(), "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryStore{users: []model.User{{ID: "admin", Email: "admin@example.test", Role: model.RoleAdministrator, Status: model.UserActive}}}
	service := New(repository, box)
	request := model.SMTPConfiguration{SMTPSettings: model.SMTPSettings{Enabled: true, Host: "smtp.example.test", Port: 587, Username: "admin", FromAddress: "mossward@example.test", TLSMode: "starttls", RecipientUserIDs: []string{"admin"}}, Password: "secret"}
	saved, err := service.Configure(request, "admin", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if string(saved.PasswordCiphertext) == request.Password || len(saved.PasswordCiphertext) == 0 {
		t.Fatal("SMTP password was not encrypted")
	}
	plaintext, err := box.Decrypt(saved.PasswordCiphertext)
	if err != nil || string(plaintext) != "secret" {
		t.Fatal("SMTP password did not decrypt")
	}
}
