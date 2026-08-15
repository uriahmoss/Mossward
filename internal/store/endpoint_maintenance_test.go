package store

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestEndpointMaintenanceSuppressesOnlyDuringActiveUncancelledWindow(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at) VALUES('endpoint','Endpoint','active','serial','cert',?,?)`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	window := model.EndpointMaintenanceWindow{ID: "window", Name: "Patch", TargetType: model.MaintenanceTargetEndpoint, TargetID: "endpoint",
		StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), Reason: "approved patching", CreatedBy: "admin", CreatedAt: now}
	event := model.AuditEvent{OccurredAt: now, Action: "endpoint.maintenance.created", Severity: model.AuditWarning, TargetType: "endpoint_maintenance", TargetID: window.ID}
	if err := repository.CreateEndpointMaintenanceWindow(window, event); err != nil {
		t.Fatal(err)
	}
	active, err := repository.EndpointInMaintenance("endpoint", now)
	if err != nil || !active {
		t.Fatalf("active maintenance = %t, error = %v", active, err)
	}
	cancelEvent := model.AuditEvent{OccurredAt: now, Action: "endpoint.maintenance.cancelled", Severity: model.AuditWarning, TargetType: "endpoint_maintenance", TargetID: window.ID}
	if err := repository.CancelEndpointMaintenanceWindow(window.ID, "admin", now, cancelEvent); err != nil {
		t.Fatal(err)
	}
	active, err = repository.EndpointInMaintenance("endpoint", now)
	if err != nil || active {
		t.Fatalf("cancelled maintenance = %t, error = %v", active, err)
	}
	windows, err := repository.ListEndpointMaintenanceWindows()
	if err != nil || len(windows) != 1 || windows[0].CancelledAt == nil || windows[0].Reason != "approved patching" {
		t.Fatalf("retained maintenance history = %#v, error = %v", windows, err)
	}
	var count int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE target_type='endpoint_maintenance'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("maintenance audit count = %d, error = %v", count, err)
	}
}
