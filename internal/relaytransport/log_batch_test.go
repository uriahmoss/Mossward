package relaytransport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func TestAgentLogBatchRoundTripAndProvenance(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	records := []AgentLogRecord{
		{GeneratedAt: now.Add(-time.Minute), Level: AgentLogInfo, Component: "agent", Message: "started"},
		{GeneratedAt: now, Level: AgentLogWarning, Component: "integrity", Message: "configuration changed"},
	}
	batch, err := BuildAgentLogBatch("endpoint", 7, records, now, key)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenAgentLogBatch(batch, "endpoint", 7, &key.PublicKey)
	if err != nil || len(opened) != len(records) || opened[1].Message != records[1].Message || batch.Header.Source != agentLogSource {
		t.Fatalf("opened log batch = %#v, header = %#v, error = %v", opened, batch.Header, err)
	}
	if _, err := OpenAgentLogBatch(batch, "other-endpoint", 7, &key.PublicKey); err == nil {
		t.Fatal("log batch was accepted for a different endpoint")
	}
	if _, err := OpenAgentLogBatch(batch, "endpoint", 8, &key.PublicKey); err == nil {
		t.Fatal("log batch was accepted with a different sequence")
	}
	batch.CompressedRecords[0] ^= 1
	if _, err := OpenAgentLogBatch(batch, "endpoint", 7, &key.PublicKey); err == nil {
		t.Fatal("altered compressed log batch was accepted")
	}
}
