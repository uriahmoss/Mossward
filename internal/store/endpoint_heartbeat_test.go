package store

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestEndpointHeartbeatSettingsDefaultAndAuditUpdate(t *testing.T) {
	repository := openTestStore(t)
	settings, err := repository.EndpointHeartbeatSettings()
	if err != nil || !settings.Enabled || settings.MissedAfterMinutes != 5 || settings.StaleAfterMinutes != 30 {
		t.Fatalf("default heartbeat settings = %#v, error = %v", settings, err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	settings.MissedAfterMinutes = 10
	settings.StaleAfterMinutes = 60
	settings.UpdatedBy = "admin"
	settings.UpdatedAt = now
	event := model.AuditEvent{OccurredAt: now, Action: "endpoint.heartbeat_settings.updated", Severity: model.AuditInfo, TargetType: "endpoint_heartbeat_settings", TargetID: "global"}
	if err := repository.SetEndpointHeartbeatSettings(settings, event); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.EndpointHeartbeatSettings()
	if err != nil || stored.MissedAfterMinutes != 10 || stored.StaleAfterMinutes != 60 || !stored.UpdatedAt.Equal(now) {
		t.Fatalf("stored heartbeat settings = %#v, error = %v", stored, err)
	}
	var count int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action='endpoint.heartbeat_settings.updated'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("heartbeat settings audit count = %d, error = %v", count, err)
	}
}
