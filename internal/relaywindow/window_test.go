package relaywindow

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestWindowUsesConfiguredTimezoneAndSupportsOvernightRanges(t *testing.T) {
	window := model.RelayUploadWindow{Name: "overnight", TargetType: model.MaintenanceTargetEndpoint, TargetID: "endpoint",
		Timezone: "America/Chicago", Days: []time.Weekday{time.Monday}, StartMinute: 22 * 60, EndMinute: 2 * 60, Enabled: true}
	for _, test := range []struct {
		at   string
		open bool
	}{{"2026-08-18T04:00:00Z", true}, {"2026-08-18T06:59:00Z", true}, {"2026-08-18T07:00:00Z", false}} {
		at, err := time.Parse(time.RFC3339, test.at)
		if err != nil {
			t.Fatal(err)
		}
		open, err := Open(window, at)
		if err != nil || open != test.open {
			t.Fatalf("window open at %s = %t, error = %v", test.at, open, err)
		}
	}
}

func TestWindowFailsClosedForInvalidOrDisabledPolicy(t *testing.T) {
	window := model.RelayUploadWindow{Name: "window", TargetType: model.MaintenanceTargetEndpoint, TargetID: "endpoint",
		Timezone: "Not/AZone", Days: []time.Weekday{time.Monday}, StartMinute: 60, EndMinute: 120, Enabled: true}
	if open, err := Open(window, time.Now()); err == nil || open {
		t.Fatalf("invalid timezone result = %t, %v", open, err)
	}
	window.Timezone, window.Enabled = "UTC", false
	if open, err := Open(window, time.Now()); err != nil || open {
		t.Fatalf("disabled window result = %t, %v", open, err)
	}
}
