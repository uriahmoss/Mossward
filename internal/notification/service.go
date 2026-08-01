package notification

import (
	"crypto/tls"
	"errors"
	"fmt"
	"mossward/internal/auth"
	"mossward/internal/model"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type Store interface {
	SMTPSettings() (model.SMTPSettings, error)
	SaveSMTPSettings(model.SMTPSettings, model.AuditEvent) error
	ListUsers() ([]model.User, error)
}
type Service struct {
	store   Store
	secrets *auth.SecretBox
}

func New(repository Store, secrets *auth.SecretBox) *Service {
	return &Service{store: repository, secrets: secrets}
}
func (s *Service) Settings() (model.SMTPSettings, error) { return s.store.SMTPSettings() }
func (s *Service) Configure(request model.SMTPConfiguration, actorID, sourceIP string) (model.SMTPSettings, error) {
	value := request.SMTPSettings
	value.Host = strings.TrimSpace(value.Host)
	value.Username = strings.TrimSpace(value.Username)
	value.FromAddress = strings.TrimSpace(value.FromAddress)
	value.TLSMode = strings.ToLower(strings.TrimSpace(value.TLSMode))
	if err := s.validate(value); err != nil {
		return value, err
	}
	if value.Enabled {
		parsed, _ := mail.ParseAddress(value.FromAddress)
		value.FromAddress = parsed.Address
	}
	current, err := s.store.SMTPSettings()
	if err != nil {
		return value, err
	}
	if request.Password != "" {
		value.PasswordCiphertext, err = s.secrets.Encrypt([]byte(request.Password))
		if err != nil {
			return value, err
		}
	} else {
		value.PasswordCiphertext = current.PasswordCiphertext
	}
	value.HasPassword = len(value.PasswordCiphertext) > 0
	now := time.Now().UTC()
	event := model.AuditEvent{OccurredAt: now, ActorID: actorID, Action: "notification.smtp.configured", Severity: model.AuditWarning, TargetType: "smtp_settings", TargetID: "server", SourceIP: sourceIP, Details: "{}"}
	return value, s.store.SaveSMTPSettings(value, event)
}
func (s *Service) validate(value model.SMTPSettings) error {
	if !value.Enabled {
		return nil
	}
	if value.Host == "" || value.Port < 1 || value.Port > 65535 {
		return errors.New("SMTP host and valid port are required")
	}
	if value.TLSMode != "starttls" && value.TLSMode != "tls" {
		return errors.New("SMTP TLS mode must be starttls or tls")
	}
	if _, err := mail.ParseAddress(value.FromAddress); err != nil {
		return errors.New("SMTP from address is invalid")
	}
	users, err := s.store.ListUsers()
	if err != nil {
		return err
	}
	admins := map[string]bool{}
	for _, user := range users {
		if user.Role == model.RoleAdministrator && user.Status == model.UserActive {
			admins[user.ID] = true
		}
	}
	if len(value.RecipientUserIDs) == 0 {
		return errors.New("select at least one active Administrator recipient")
	}
	for _, id := range value.RecipientUserIDs {
		if !admins[id] {
			return errors.New("SMTP recipients must be active Administrators")
		}
	}
	return nil
}
func (s *Service) SendLongRun(policy model.ReusableScanPolicy, scan model.Scan) error {
	settings, err := s.store.SMTPSettings()
	if err != nil || !settings.Enabled {
		return err
	}
	password, err := s.secrets.Decrypt(settings.PasswordCiphertext)
	if err != nil && len(settings.PasswordCiphertext) > 0 {
		return err
	}
	users, err := s.store.ListUsers()
	if err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, id := range settings.RecipientUserIDs {
		wanted[id] = true
	}
	recipients := []string{}
	for _, user := range users {
		if wanted[user.ID] && user.Role == model.RoleAdministrator && user.Status == model.UserActive {
			recipients = append(recipients, user.Email)
		}
	}
	if len(recipients) == 0 {
		return errors.New("no active SMTP recipients")
	}
	subject := strings.NewReplacer("\r", " ", "\n", " ").Replace(policy.Name)
	body := fmt.Sprintf("Mossward scan %q has exceeded its configured active-runtime alert threshold.\r\n\r\nScan ID: %s\r\nActive runtime: %s\r\nStatus: %s\r\n", policy.Name, scan.ID, time.Duration(scan.ActiveSeconds)*time.Second, scan.Status)
	message := []byte("From: " + settings.FromAddress + "\r\nTo: " + strings.Join(recipients, ",") + "\r\nSubject: Mossward scan running long: " + subject + "\r\n\r\n" + body)
	return sendSMTP(settings, string(password), recipients, message)
}
func sendSMTP(settings model.SMTPSettings, password string, recipients []string, message []byte) error {
	address := net.JoinHostPort(settings.Host, strconv.Itoa(settings.Port))
	var client *smtp.Client
	var err error
	if settings.TLSMode == "tls" {
		connection, dialErr := tls.Dial("tcp", address, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: settings.Host})
		if dialErr != nil {
			return dialErr
		}
		client, err = smtp.NewClient(connection, settings.Host)
	} else {
		client, err = smtp.Dial(address)
		if err == nil {
			err = client.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: settings.Host})
		}
	}
	if err != nil {
		return err
	}
	defer client.Close()
	if settings.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", settings.Username, password, settings.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(settings.FromAddress); err != nil {
		return err
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}
