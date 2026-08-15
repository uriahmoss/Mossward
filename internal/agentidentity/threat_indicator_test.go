package agentidentity

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestNormalizeThreatIndicatorCanonicalizesSafeExactValues(t *testing.T) {
	now := time.Now().UTC()
	indicator := model.ThreatIndicator{Type: model.ThreatIndicatorHostname, Value: "Service.Example.Test.", Source: " Internal feed ", Confidence: "HIGH", ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
	if err := normalizeThreatIndicator(&indicator, now); err != nil {
		t.Fatal(err)
	}
	if indicator.Value != "service.example.test" || indicator.Source != "Internal feed" || indicator.Confidence != "high" {
		t.Fatalf("normalized indicator = %#v", indicator)
	}
}

func TestNormalizeThreatIndicatorRejectsUnsafeOrStaleValues(t *testing.T) {
	now := time.Now().UTC()
	tests := []model.ThreatIndicator{
		{Type: model.ThreatIndicatorHostname, Value: "*.example.test", Source: "feed", Confidence: "high", ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)},
		{Type: model.ThreatIndicatorIP, Value: "192.0.2.0/24", Source: "feed", Confidence: "high", ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)},
		{Type: model.ThreatIndicatorIP, Value: "192.0.2.1", Source: "feed", Confidence: "high", ObservedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
	}
	for _, indicator := range tests {
		if err := normalizeThreatIndicator(&indicator, now); err == nil {
			t.Fatalf("accepted unsafe or stale indicator %#v", indicator)
		}
	}
}
