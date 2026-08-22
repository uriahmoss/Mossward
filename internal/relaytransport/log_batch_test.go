package relaytransport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
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
		{GeneratedAt: now.Add(-time.Minute), Source: AgentLogSourceMossward, Level: AgentLogInfo, Component: AgentComponentAgent, Message: "started"},
		{GeneratedAt: now, Source: AgentLogSourceMossward, Level: AgentLogWarning, Component: AgentComponentIntegrity, Message: "configuration changed"},
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

func TestAgentLogBatchReadsLegacyQueuedRecords(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	records := []AgentLogRecord{{GeneratedAt: now, Level: AgentLogInfo, Component: AgentComponentAgent, Message: "legacy queued record"}}
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := compressAgentLogs(encoded)
	if err != nil {
		t.Fatal(err)
	}
	batch := SignedCompressedAgentLogBatch{Header: AgentLogBatchHeader{SchemaVersion: legacyAgentLogBatchVersion, BatchID: "legacy-batch",
		SourceEndpointID: "endpoint", Source: agentLogSource, Sequence: 1, RecordCount: 1, FirstGeneratedAt: now,
		LastGeneratedAt: now, CreatedAt: now, Compression: agentLogCompression, UncompressedBytes: len(encoded)}, CompressedRecords: compressed}
	digest, err := agentLogBatchDigest(batch.Header, batch.CompressedRecords)
	if err != nil {
		t.Fatal(err)
	}
	batch.Signature, err = ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenAgentLogBatch(batch, "endpoint", 1, &key.PublicKey)
	if err != nil || len(opened) != 1 || opened[0].Message != records[0].Message {
		t.Fatalf("legacy queued batch = %#v, error = %v", opened, err)
	}
}
