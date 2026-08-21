package relaytransport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestDelayedQueueStoresEncryptedHeartbeatAndAgentLogs(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "relay", "queue.db"), QueueLimits{MaxItems: 2, MaxBytes: 8 << 20, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	delayed, err := NewDelayedQueue(queue, "endpoint", "server", signingKey, serverKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := model.AgentCheckIn{SchemaVersion: 2, GeneratedAt: now, SoftwareVersion: "1.0.0", OperatingSystem: "linux", Architecture: "amd64"}
	if _, err := delayed.EnqueueHeartbeat(heartbeat, 1, now); err != nil {
		t.Fatal(err)
	}
	frame, err := queue.Peek(now)
	if err != nil || frame.Kind != MessageAgentCheckIn {
		t.Fatalf("queued heartbeat frame = %#v, error = %v", frame, err)
	}
	plaintext, err := Open(frame, serverKey, &signingKey.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := DecodeDelayedTelemetry(frame.Kind, plaintext)
	if err != nil || envelope.Heartbeat == nil || envelope.Heartbeat.SoftwareVersion != "1.0.0" {
		t.Fatalf("decrypted heartbeat envelope = %#v, error = %v", envelope, err)
	}
	if err := queue.Acknowledge(frame.MessageID); err != nil {
		t.Fatal(err)
	}
	records := []AgentLogRecord{{GeneratedAt: now, Level: AgentLogWarning, Component: "integrity", Message: "configuration changed"}}
	if _, err := delayed.EnqueueAgentLogs(records, 2, now, now); err != nil {
		t.Fatal(err)
	}
	frame, err = queue.Peek(now)
	if err != nil || frame.Kind != MessageAgentLogBatch {
		t.Fatalf("queued agent-log frame = %#v, error = %v", frame, err)
	}
}

func TestDelayedQueueRejectsNonAgentLogData(t *testing.T) {
	record := AgentLogRecord{GeneratedAt: time.Now(), Level: "syslog", Component: "external", Message: "unsupported"}
	if err := validateAgentLogRecord(record); err == nil {
		t.Fatal("unsupported external log type was accepted")
	}
}

func TestDelayedTelemetryDecoderRejectsMixedKinds(t *testing.T) {
	now := time.Now().UTC()
	mixed := DelayedTelemetryEnvelope{SchemaVersion: delayedTelemetrySchemaVersion, Kind: MessageAgentCheckIn,
		Heartbeat: &model.AgentCheckIn{SchemaVersion: 2, GeneratedAt: now},
		AgentLogs: []AgentLogRecord{{GeneratedAt: now, Level: AgentLogInfo, Component: "agent", Message: "started"}}}
	payload, err := json.Marshal(mixed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDelayedTelemetry(MessageAgentCheckIn, payload); err == nil {
		t.Fatal("mixed delayed telemetry envelope was accepted")
	}
}
