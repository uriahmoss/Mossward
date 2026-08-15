package agentidentity

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestEndpointHeartbeatAlertsEscalateWithoutDuplication(t *testing.T) {
	now := time.Now().UTC()
	settings := model.EndpointHeartbeatSettings{Enabled: true, MissedAfterMinutes: 5, StaleAfterMinutes: 30}
	endpoint := model.Endpoint{Status: model.EndpointActive, EnrolledAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(90 * 24 * time.Hour)}
	alerts := endpointAlerts(endpoint, settings, now)
	if len(alerts) != 1 || alerts[0].Code != "heartbeat_missed" {
		t.Fatalf("missed heartbeat alerts = %#v", alerts)
	}
	lastSeen := now.Add(-31 * time.Minute)
	endpoint.LastSeenAt = &lastSeen
	alerts = endpointAlerts(endpoint, settings, now)
	if len(alerts) != 1 || alerts[0].Code != "agent_stale" || alerts[0].Severity != "error" {
		t.Fatalf("stale heartbeat alerts = %#v", alerts)
	}
	settings.Enabled = false
	if alerts = endpointAlerts(endpoint, settings, now); len(alerts) != 0 {
		t.Fatalf("disabled heartbeat alerts = %#v", alerts)
	}
}
