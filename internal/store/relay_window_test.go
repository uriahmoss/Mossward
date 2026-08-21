package store

import (
	"errors"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestRelayUploadWindowsPersistTargetsTimezoneAndAudit(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at) VALUES('endpoint','Endpoint','active','serial','cert',?,?)`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	window := model.RelayUploadWindow{ID: "window", Name: "Overnight", TargetType: model.MaintenanceTargetEndpoint, TargetID: "endpoint",
		Timezone: "America/Chicago", Days: []time.Weekday{time.Monday, time.Wednesday}, StartMinute: 60, EndMinute: 360,
		Enabled: true, Reason: "guarded network", CreatedBy: "admin", CreatedAt: now, UpdatedBy: "admin", UpdatedAt: now}
	event := model.AuditEvent{OccurredAt: now, Action: "endpoint.relay_upload_window.created", Severity: model.AuditWarning,
		TargetType: "relay_upload_window", TargetID: window.ID}
	if err := repository.UpsertRelayUploadWindow(window, event); err != nil {
		t.Fatal(err)
	}
	windows, err := repository.ListRelayUploadWindows()
	if err != nil || len(windows) != 1 || windows[0].Timezone != window.Timezone || len(windows[0].Days) != 2 || !windows[0].Enabled {
		t.Fatalf("stored relay upload windows = %#v, error = %v", windows, err)
	}
	window.Enabled, window.UpdatedAt = false, now.Add(time.Minute)
	event.Action = "endpoint.relay_upload_window.updated"
	if err := repository.UpsertRelayUploadWindow(window, event); err != nil {
		t.Fatal(err)
	}
	windows, err = repository.ListRelayUploadWindows()
	if err != nil || len(windows) != 1 || windows[0].Enabled {
		t.Fatalf("updated relay upload window = %#v, error = %v", windows, err)
	}
	var audits int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE target_type='relay_upload_window' AND target_id=?`, window.ID).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("relay upload-window audit count = %d, error = %v", audits, err)
	}
}

func TestRelayUploadWindowRequiresExistingTarget(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC()
	window := model.RelayUploadWindow{ID: "window", Name: "Window", TargetType: model.MaintenanceTargetEndpoint, TargetID: "missing",
		Timezone: "UTC", Days: []time.Weekday{time.Monday}, StartMinute: 60, EndMinute: 120, Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := repository.UpsertRelayUploadWindow(window, model.AuditEvent{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing relay upload-window target result = %v", err)
	}
}
