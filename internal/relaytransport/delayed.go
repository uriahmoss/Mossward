package relaytransport

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"mossward/internal/model"
)

const (
	delayedTelemetrySchemaVersion = 1
	compressedLogEnvelopeVersion  = 2
	maximumDelayedHeartbeatBytes  = 3 << 20
	maximumAgentLogRecords        = 512
	maximumAgentLogMessageBytes   = 2048
	maximumAgentLogComponentBytes = 100
)

type AgentLogLevel string

const (
	AgentLogInfo    AgentLogLevel = "info"
	AgentLogWarning AgentLogLevel = "warning"
	AgentLogError   AgentLogLevel = "error"
)

type AgentLogRecord struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Level       AgentLogLevel `json:"level"`
	Component   string        `json:"component"`
	Message     string        `json:"message"`
}

type DelayedTelemetryEnvelope struct {
	SchemaVersion int                            `json:"schema_version"`
	Kind          MessageKind                    `json:"kind"`
	Heartbeat     *model.AgentCheckIn            `json:"heartbeat,omitempty"`
	AgentLogs     []AgentLogRecord               `json:"agent_logs,omitempty"`
	AgentLogBatch *SignedCompressedAgentLogBatch `json:"agent_log_batch,omitempty"`
}

type DelayedQueue struct {
	queue      *Queue
	endpointID string
	serverID   string
	signingKey *ecdsa.PrivateKey
	serverKey  *ecdh.PublicKey
}

func NewDelayedQueue(queue *Queue, endpointID, serverID string, signingKey *ecdsa.PrivateKey, serverKey *ecdh.PublicKey) (*DelayedQueue, error) {
	if queue == nil || strings.TrimSpace(endpointID) == "" || strings.TrimSpace(serverID) == "" || signingKey == nil || serverKey == nil {
		return nil, errors.New("delayed telemetry queue configuration is invalid")
	}
	return &DelayedQueue{queue: queue, endpointID: endpointID, serverID: serverID, signingKey: signingKey, serverKey: serverKey}, nil
}

func (q *DelayedQueue) EnqueueHeartbeat(checkIn model.AgentCheckIn, sequence uint64, now time.Time) (string, error) {
	if checkIn.SchemaVersion != 2 || checkIn.GeneratedAt.IsZero() || sequence == 0 {
		return "", errors.New("delayed heartbeat is invalid")
	}
	envelope := DelayedTelemetryEnvelope{SchemaVersion: delayedTelemetrySchemaVersion, Kind: MessageAgentCheckIn, Heartbeat: &checkIn}
	return q.enqueue(envelope, MessageAgentCheckIn, sequence, checkIn.GeneratedAt, now, maximumDelayedHeartbeatBytes)
}

func (q *DelayedQueue) EnqueueAgentLogs(records []AgentLogRecord, sequence uint64, generatedAt, now time.Time) (string, error) {
	if sequence == 0 || generatedAt.IsZero() || len(records) == 0 || len(records) > maximumAgentLogRecords {
		return "", errors.New("delayed Mossward agent-log batch is invalid")
	}
	for _, record := range records {
		if err := validateAgentLogRecord(record); err != nil {
			return "", err
		}
	}
	batch, err := BuildAgentLogBatch(q.endpointID, sequence, records, generatedAt, q.signingKey)
	if err != nil {
		return "", err
	}
	envelope := DelayedTelemetryEnvelope{SchemaVersion: compressedLogEnvelopeVersion, Kind: MessageAgentLogBatch, AgentLogBatch: &batch}
	return q.enqueue(envelope, MessageAgentLogBatch, sequence, generatedAt, now, MaximumCiphertextSize/2)
}

func (q *DelayedQueue) enqueue(envelope DelayedTelemetryEnvelope, kind MessageKind, sequence uint64, generatedAt, now time.Time, payloadLimit int) (string, error) {
	payload, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	if len(payload) == 0 || len(payload) > payloadLimit {
		return "", errors.New("delayed telemetry payload exceeds its limit")
	}
	messageID, err := randomMessageID()
	if err != nil {
		return "", err
	}
	frame := Frame{MessageID: messageID, Kind: kind, DownstreamEndpointID: q.endpointID, SenderID: q.endpointID,
		RecipientID: q.serverID, Sequence: sequence, CreatedAt: generatedAt.UTC()}
	sealed, err := Seal(frame, payload, q.signingKey, q.serverKey)
	if err != nil {
		return "", err
	}
	if err := q.queue.Enqueue(sealed, now); err != nil {
		return "", err
	}
	return messageID, nil
}

func DecodeDelayedTelemetry(kind MessageKind, payload []byte) (DelayedTelemetryEnvelope, error) {
	var envelope DelayedTelemetryEnvelope
	if len(payload) == 0 || len(payload) > maximumDelayedHeartbeatBytes {
		return envelope, errors.New("delayed telemetry payload size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return DelayedTelemetryEnvelope{}, errors.New("delayed telemetry envelope is invalid")
	}
	if envelope.Kind != kind {
		return DelayedTelemetryEnvelope{}, errors.New("delayed telemetry kind or schema is invalid")
	}
	switch kind {
	case MessageAgentCheckIn:
		if envelope.SchemaVersion != delayedTelemetrySchemaVersion || envelope.Heartbeat == nil || len(envelope.AgentLogs) != 0 || envelope.AgentLogBatch != nil || envelope.Heartbeat.SchemaVersion != 2 || envelope.Heartbeat.GeneratedAt.IsZero() {
			return DelayedTelemetryEnvelope{}, errors.New("delayed heartbeat envelope is invalid")
		}
	case MessageAgentLogBatch:
		if envelope.SchemaVersion == compressedLogEnvelopeVersion && envelope.Heartbeat == nil && len(envelope.AgentLogs) == 0 && envelope.AgentLogBatch != nil {
			return envelope, nil
		}
		if envelope.SchemaVersion != delayedTelemetrySchemaVersion || envelope.Heartbeat != nil || envelope.AgentLogBatch != nil || len(envelope.AgentLogs) == 0 || len(envelope.AgentLogs) > maximumAgentLogRecords {
			return DelayedTelemetryEnvelope{}, errors.New("delayed agent-log envelope is invalid")
		}
		for _, record := range envelope.AgentLogs {
			if err := validateAgentLogRecord(record); err != nil {
				return DelayedTelemetryEnvelope{}, err
			}
		}
	default:
		return DelayedTelemetryEnvelope{}, errors.New("unsupported delayed telemetry kind")
	}
	return envelope, nil
}

func validateAgentLogRecord(record AgentLogRecord) error {
	if record.GeneratedAt.IsZero() || strings.TrimSpace(record.Component) == "" || len(record.Component) > maximumAgentLogComponentBytes ||
		strings.TrimSpace(record.Message) == "" || len(record.Message) > maximumAgentLogMessageBytes {
		return errors.New("Mossward agent-log record is invalid")
	}
	switch record.Level {
	case AgentLogInfo, AgentLogWarning, AgentLogError:
		return nil
	default:
		return errors.New("Mossward agent-log level is invalid")
	}
}

func randomMessageID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
