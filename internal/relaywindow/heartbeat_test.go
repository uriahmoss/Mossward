package relaywindow

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestHeartbeatAlertsSuppressDuringWindowAndGrace(t *testing.T) {
	window := model.RelayUploadWindow{ID: "window", Name: "Window", TargetType: model.MaintenanceTargetEndpoint, TargetID: "endpoint",
		Timezone: "UTC", Days: []time.Weekday{time.Thursday}, StartMinute: 60, EndMinute: 120, Enabled: true}
	policy := model.ResolvedDelayedHeartbeatPolicy{AllowDelayedHeartbeats: true, PostWindowGraceMinutes: 30}
	for _, test := range []struct {
		at     time.Time
		reason string
		want   bool
	}{
		{time.Date(2026, time.August, 20, 1, 30, 0, 0, time.UTC), "upload_window_open", true},
		{time.Date(2026, time.August, 20, 2, 20, 0, 0, time.UTC), "post_window_grace", true},
		{time.Date(2026, time.August, 20, 2, 31, 0, 0, time.UTC), "outside_post_window_grace", false},
	} {
		result, err := HeartbeatAlertSuppression([]model.RelayUploadWindow{window}, policy, test.at)
		if err != nil || result.Suppressed != test.want || result.Reason != test.reason {
			t.Fatalf("heartbeat suppression at %s = %#v, error = %v", test.at, result, err)
		}
	}
}

func TestHeartbeatAlertsDoNotSuppressWithoutPermission(t *testing.T) {
	result, err := HeartbeatAlertSuppression(nil, model.ResolvedDelayedHeartbeatPolicy{}, time.Now())
	if err != nil || result.Suppressed || result.Reason != "delayed_heartbeats_not_allowed" {
		t.Fatalf("default heartbeat suppression = %#v, error = %v", result, err)
	}
}
