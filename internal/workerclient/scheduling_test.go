package workerclient

import (
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestOutboxBackpressurePausesPollingWithoutBlockingForwarding(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	outbox, err := OpenOutbox(filepath.Join(directory, "outbox.db"), filepath.Join(directory, "outbox.key"), OutboxLimits{MaxItems: 10, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer outbox.Close()
	policy := DefaultBackpressurePolicy()
	for index := range 10 {
		if err := outbox.Enqueue(OutboxMessage{ID: fmt.Sprintf("message-%02d", index), Kind: OutboxEvidence,
			Payload: []byte("x"), CreatedAt: time.Now().UTC().Add(time.Duration(index) * time.Second)}); err != nil {
			t.Fatal(err)
		}
		state, err := outbox.Backpressure(policy)
		if err != nil {
			t.Fatal(err)
		}
		expected := OutboxPressureNormal
		if index >= 9 {
			expected = OutboxPressureFull
		} else if index >= 8 {
			expected = OutboxPressureCritical
		} else if index >= 7 {
			expected = OutboxPressureElevated
		}
		if state.Pressure != expected || state.ForwardPending != true || state.AcceptNewJobs != (expected == OutboxPressureNormal) {
			t.Fatalf("unexpected pressure after %d messages: %#v", index+1, state)
		}
	}
}

func TestRetrySchedulerUsesCappedPositiveJitterAndRetryAfter(t *testing.T) {
	scheduler, err := NewRetryScheduler(RetryPolicy{InitialDelay: 10 * time.Second, MaximumDelay: 100 * time.Second, JitterPercent: 20})
	if err != nil {
		t.Fatal(err)
	}
	scheduler.random = func(maximum int64) (int64, error) { return maximum - 1, nil }
	tests := []struct {
		failures   int
		retryAfter time.Duration
		want       time.Duration
	}{
		{failures: 1, want: 12 * time.Second},
		{failures: 3, want: 48 * time.Second},
		{failures: 1, retryAfter: 70 * time.Second, want: 84 * time.Second},
		{failures: 8, want: 100 * time.Second},
	}
	for _, test := range tests {
		delay, err := scheduler.Delay(test.failures, test.retryAfter)
		if err != nil || delay != test.want {
			t.Fatalf("Delay(%d,%s)=%s,%v want %s", test.failures, test.retryAfter, delay, err, test.want)
		}
	}
}

func TestParseRetryAfterSupportsSecondsAndHTTPDate(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	if delay := ParseRetryAfter("30", now); delay != 30*time.Second {
		t.Fatalf("numeric Retry-After = %s", delay)
	}
	if delay := ParseRetryAfter(now.Add(45*time.Second).Format(http.TimeFormat), now); delay != 45*time.Second {
		t.Fatalf("dated Retry-After = %s", delay)
	}
	if delay := ParseRetryAfter("invalid", now); delay != 0 {
		t.Fatalf("invalid Retry-After = %s", delay)
	}
}
