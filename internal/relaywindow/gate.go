package relaywindow

import (
	"context"
	"errors"
	"time"

	"mossward/internal/model"
)

var ErrConnectionWindowClosed = errors.New("relay server connection window is closed")

const maximumClockDrift = 5 * time.Minute

type GateDecision struct {
	Allowed           bool      `json:"allowed"`
	Reason            string    `json:"reason"`
	WindowIDs         []string  `json:"window_ids"`
	EvaluatedAt       time.Time `json:"evaluated_at"`
	ClockDriftSeconds int64     `json:"clock_drift_seconds"`
}

type ServerConnector func(context.Context) error

func Evaluate(windows []model.RelayUploadWindow, agentNow, trustedServerNow time.Time) GateDecision {
	if agentNow.IsZero() || trustedServerNow.IsZero() {
		return GateDecision{Reason: "invalid_evaluation_time", WindowIDs: []string{}}
	}
	drift := absoluteDuration(agentNow.Sub(trustedServerNow))
	decision := GateDecision{Reason: "no_enabled_window", WindowIDs: []string{}, EvaluatedAt: trustedServerNow.UTC(), ClockDriftSeconds: int64(drift.Seconds())}
	if drift > maximumClockDrift {
		decision.Reason = "clock_drift_detected"
		return decision
	}
	enabled := false
	seen := make(map[string]bool, len(windows))
	for _, window := range windows {
		if window.ID == "" || seen[window.ID] {
			return GateDecision{Reason: "invalid_window_policy", WindowIDs: []string{}, EvaluatedAt: trustedServerNow.UTC(), ClockDriftSeconds: decision.ClockDriftSeconds}
		}
		seen[window.ID] = true
		open, err := Open(window, trustedServerNow)
		if err != nil {
			return GateDecision{Reason: "invalid_window_policy", WindowIDs: []string{}, EvaluatedAt: trustedServerNow.UTC(), ClockDriftSeconds: decision.ClockDriftSeconds}
		}
		if !window.Enabled {
			continue
		}
		enabled = true
		if open {
			decision.WindowIDs = append(decision.WindowIDs, window.ID)
		}
	}
	if len(decision.WindowIDs) > 0 {
		decision.Allowed, decision.Reason = true, "approved_window_open"
		return decision
	}
	if enabled {
		decision.Reason = "outside_approved_window"
	}
	return decision
}

func Connect(ctx context.Context, windows []model.RelayUploadWindow, agentNow, trustedServerNow time.Time, connector ServerConnector) (GateDecision, error) {
	if connector == nil {
		return GateDecision{}, errors.New("relay server connector is required")
	}
	decision := Evaluate(windows, agentNow, trustedServerNow)
	if !decision.Allowed {
		return decision, ErrConnectionWindowClosed
	}
	if err := ctx.Err(); err != nil {
		return decision, err
	}
	return decision, connector(ctx)
}

func absoluteDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}
