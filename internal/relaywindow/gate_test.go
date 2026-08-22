package relaywindow

import (
	"context"
	"errors"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestConnectInvokesServerOnlyInsideApprovedWindow(t *testing.T) {
	now := time.Date(2026, time.August, 20, 1, 30, 0, 0, time.UTC)
	window := model.RelayUploadWindow{ID: "window", Name: "Window", TargetType: model.MaintenanceTargetEndpoint, TargetID: "endpoint",
		Timezone: "UTC", Days: []time.Weekday{time.Thursday}, StartMinute: 60, EndMinute: 120, Enabled: true}
	connections := 0
	connector := func(context.Context) error { connections++; return nil }
	decision, err := Connect(context.Background(), []model.RelayUploadWindow{window}, now, now, connector)
	if err != nil || !decision.Allowed || connections != 1 || len(decision.WindowIDs) != 1 {
		t.Fatalf("open window decision = %#v, connections = %d, error = %v", decision, connections, err)
	}
	decision, err = Connect(context.Background(), []model.RelayUploadWindow{window}, now.Add(2*time.Hour), now.Add(2*time.Hour), connector)
	if !errors.Is(err, ErrConnectionWindowClosed) || decision.Allowed || connections != 1 || decision.Reason != "outside_approved_window" {
		t.Fatalf("closed window decision = %#v, connections = %d, error = %v", decision, connections, err)
	}
}

func TestConnectionGateFailsClosedForMissingOrInvalidPolicy(t *testing.T) {
	called := false
	connector := func(context.Context) error { called = true; return nil }
	now := time.Now()
	decision, err := Connect(context.Background(), nil, now, now, connector)
	if !errors.Is(err, ErrConnectionWindowClosed) || decision.Reason != "no_enabled_window" || called {
		t.Fatalf("missing policy decision = %#v, called = %t, error = %v", decision, called, err)
	}
	invalid := model.RelayUploadWindow{ID: "invalid", Enabled: true}
	decision, err = Connect(context.Background(), []model.RelayUploadWindow{invalid}, now, now, connector)
	if !errors.Is(err, ErrConnectionWindowClosed) || decision.Reason != "invalid_window_policy" || called {
		t.Fatalf("invalid policy decision = %#v, called = %t, error = %v", decision, called, err)
	}
}

func TestConnectionGateRejectsAmbiguousDuplicatePolicies(t *testing.T) {
	now := time.Date(2026, time.August, 20, 1, 30, 0, 0, time.UTC)
	window := model.RelayUploadWindow{ID: "duplicate", Name: "Window", TargetType: model.MaintenanceTargetEndpoint, TargetID: "endpoint",
		Timezone: "UTC", Days: []time.Weekday{time.Thursday}, StartMinute: 60, EndMinute: 120, Enabled: true}
	decision := Evaluate([]model.RelayUploadWindow{window, window}, now, now)
	if decision.Allowed || decision.Reason != "invalid_window_policy" {
		t.Fatalf("duplicate policy decision = %#v", decision)
	}
}

func TestConnectionGateUsesTrustedServerTimeAndRejectsClockDrift(t *testing.T) {
	serverNow := time.Date(2026, time.August, 20, 3, 30, 0, 0, time.UTC)
	agentNow := serverNow.Add(-2 * time.Hour)
	window := model.RelayUploadWindow{ID: "window", Name: "Window", TargetType: model.MaintenanceTargetEndpoint, TargetID: "endpoint",
		Timezone: "UTC", Days: []time.Weekday{time.Thursday}, StartMinute: 60, EndMinute: 120, Enabled: true}
	called := false
	decision, err := Connect(context.Background(), []model.RelayUploadWindow{window}, agentNow, serverNow, func(context.Context) error { called = true; return nil })
	if !errors.Is(err, ErrConnectionWindowClosed) || called || decision.Reason != "clock_drift_detected" || decision.ClockDriftSeconds != 7200 {
		t.Fatalf("clock drift decision = %#v, called = %t, error = %v", decision, called, err)
	}
}

func TestConnectionGateEvaluatesWindowUsingTrustedServerTime(t *testing.T) {
	serverNow := time.Date(2026, time.August, 20, 2, 0, 0, 0, time.UTC)
	window := model.RelayUploadWindow{ID: "window", Name: "Window", TargetType: model.MaintenanceTargetEndpoint, TargetID: "endpoint",
		Timezone: "UTC", Days: []time.Weekday{time.Thursday}, StartMinute: 60, EndMinute: 120, Enabled: true}
	decision := Evaluate([]model.RelayUploadWindow{window}, serverNow.Add(-time.Minute), serverNow)
	if decision.Allowed || decision.Reason != "outside_approved_window" || !decision.EvaluatedAt.Equal(serverNow) {
		t.Fatalf("trusted-time window decision = %#v", decision)
	}
}
