package scheduling

import (
	"mossward/internal/model"
	"testing"
	"time"
)

func TestDailyScheduleUsesPolicyTimezone(t *testing.T) {
	policy := model.ReusableScanPolicy{ScheduleKind: "daily", ScheduleExpression: "01:00", ScheduleTimezone: "America/Chicago"}
	now := time.Date(2026, 1, 10, 8, 0, 0, 0, time.UTC)
	if err := Prepare(&policy, now); err != nil {
		t.Fatal(err)
	}
	wanted := time.Date(2026, 1, 11, 7, 0, 0, 0, time.UTC)
	if policy.NextRunAt == nil || !policy.NextRunAt.Equal(wanted) {
		t.Fatalf("next run=%v want %v", policy.NextRunAt, wanted)
	}
}
func TestOvernightMaintenanceWindow(t *testing.T) {
	policy := model.ReusableScanPolicy{ScheduleTimezone: "America/Chicago", WindowStart: "22:00", WindowEnd: "06:00"}
	now := time.Date(2026, 1, 10, 9, 0, 0, 0, time.UTC)
	inside, end, err := Window(policy, now)
	if err != nil || !inside {
		t.Fatalf("expected inside overnight window: %v %v", inside, err)
	}
	wanted := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	if end == nil || !end.Equal(wanted) {
		t.Fatalf("window end=%v want %v", end, wanted)
	}
}
func TestAdvancedCronValidation(t *testing.T) {
	policy := model.ReusableScanPolicy{ScheduleKind: "cron", ScheduleExpression: "not cron", ScheduleTimezone: "UTC"}
	if err := Prepare(&policy, time.Now().UTC()); err == nil {
		t.Fatal("invalid cron expression accepted")
	}
}
