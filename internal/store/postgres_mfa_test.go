package store

import (
	"testing"
	"time"
)

func TestLoginBlockTimeUsesProgressiveBoundedDelay(t *testing.T) {
	now := time.Now().UTC()
	if blocked := loginBlockTime(now, 2, 3, time.Minute, 5*time.Minute); !blocked.IsZero() {
		t.Fatalf("premature block = %s", blocked)
	}
	if blocked := loginBlockTime(now, 4, 3, time.Minute, 5*time.Minute); !blocked.Equal(now.Add(2 * time.Minute)) {
		t.Fatalf("progressive block = %s", blocked)
	}
	if blocked := loginBlockTime(now, 20, 3, time.Minute, 5*time.Minute); !blocked.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("bounded block = %s", blocked)
	}
}
