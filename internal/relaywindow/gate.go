package relaywindow

import (
	"context"
	"errors"
	"time"

	"mossward/internal/model"
)

var ErrConnectionWindowClosed = errors.New("relay server connection window is closed")

type GateDecision struct {
	Allowed     bool      `json:"allowed"`
	Reason      string    `json:"reason"`
	WindowIDs   []string  `json:"window_ids"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

type ServerConnector func(context.Context) error

func Evaluate(windows []model.RelayUploadWindow, now time.Time) GateDecision {
	if now.IsZero() {
		return GateDecision{Reason: "invalid_evaluation_time", WindowIDs: []string{}}
	}
	decision := GateDecision{Reason: "no_enabled_window", WindowIDs: []string{}, EvaluatedAt: now.UTC()}
	enabled := false
	seen := make(map[string]bool, len(windows))
	for _, window := range windows {
		if window.ID == "" || seen[window.ID] {
			return GateDecision{Reason: "invalid_window_policy", WindowIDs: []string{}, EvaluatedAt: now.UTC()}
		}
		seen[window.ID] = true
		open, err := Open(window, now)
		if err != nil {
			return GateDecision{Reason: "invalid_window_policy", WindowIDs: []string{}, EvaluatedAt: now.UTC()}
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

func Connect(ctx context.Context, windows []model.RelayUploadWindow, now time.Time, connector ServerConnector) (GateDecision, error) {
	if connector == nil {
		return GateDecision{}, errors.New("relay server connector is required")
	}
	decision := Evaluate(windows, now)
	if !decision.Allowed {
		return decision, ErrConnectionWindowClosed
	}
	if err := ctx.Err(); err != nil {
		return decision, err
	}
	return decision, connector(ctx)
}
