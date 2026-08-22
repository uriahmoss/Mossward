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
	delivery, err := queue.Claim(now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Acknowledge(frame.MessageID, delivery.Token); err != nil {
		t.Fatal(err)
	}
	records := []AgentLogRecord{{GeneratedAt: now, Source: AgentLogSourceMossward, Level: AgentLogWarning, Component: AgentComponentIntegrity, Message: "configuration changed"}}
	if _, err := delayed.EnqueueAgentLogs(records, 2, now, now); err != nil {
		t.Fatal(err)
	}
	frame, err = queue.Peek(now)
	if err != nil || frame.Kind != MessageAgentLogBatch {
		t.Fatalf("queued agent-log frame = %#v, error = %v", frame, err)
	}
	plaintext, err = Open(frame, serverKey, &signingKey.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err = DecodeDelayedTelemetry(frame.Kind, plaintext)
	if err != nil || envelope.AgentLogBatch == nil {
		t.Fatalf("compressed log envelope = %#v, error = %v", envelope, err)
	}
	openedLogs, err := OpenAgentLogBatch(*envelope.AgentLogBatch, "endpoint", frame.Sequence, &signingKey.PublicKey)
	if err != nil || len(openedLogs) != 1 || openedLogs[0].Message != records[0].Message {
		t.Fatalf("opened queued logs = %#v, error = %v", openedLogs, err)
	}
}

func TestDelayedQueueRejectsNonAgentLogData(t *testing.T) {
	for _, record := range []AgentLogRecord{
		{GeneratedAt: time.Now(), Source: "syslog", Level: AgentLogInfo, Component: AgentComponentAgent, Message: "unsupported"},
		{GeneratedAt: time.Now(), Source: "windows_event_log", Level: AgentLogInfo, Component: AgentComponentAgent, Message: "unsupported"},
		{GeneratedAt: time.Now(), Source: "application_log", Level: AgentLogInfo, Component: "third_party_app", Message: "unsupported"},
		{GeneratedAt: time.Now(), Source: AgentLogSourceMossward, Level: AgentLogInfo, Component: "third_party_app", Message: "unsupported"},
	} {
		if err := validateAgentLogRecord(record); err == nil {
			t.Fatalf("unsupported external log was accepted: %#v", record)
		}
	}
}

func TestDelayedTelemetryDecoderRejectsMixedKinds(t *testing.T) {
	now := time.Now().UTC()
	mixed := DelayedTelemetryEnvelope{SchemaVersion: delayedTelemetrySchemaVersion, Kind: MessageAgentCheckIn,
		Heartbeat: &model.AgentCheckIn{SchemaVersion: 2, GeneratedAt: now},
		AgentLogs: []AgentLogRecord{{GeneratedAt: now, Level: AgentLogInfo, Component: AgentComponentAgent, Message: "started"}}}
	payload, err := json.Marshal(mixed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDelayedTelemetry(MessageAgentCheckIn, payload); err == nil {
		t.Fatal("mixed delayed telemetry envelope was accepted")
	}
}
