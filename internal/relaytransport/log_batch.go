package relaytransport

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const (
	agentLogBatchSchemaVersion = 2
	legacyAgentLogBatchVersion = 1
	agentLogSource             = "mossward_agent"
	agentLogCompression        = "gzip"
	maximumCompressedLogBytes  = 1 << 20
	maximumExpandedLogBytes    = 2 << 20
)

type AgentLogBatchHeader struct {
	SchemaVersion     int       `json:"schema_version"`
	BatchID           string    `json:"batch_id"`
	SourceEndpointID  string    `json:"source_endpoint_id"`
	Source            string    `json:"source"`
	Sequence          uint64    `json:"sequence"`
	RecordCount       int       `json:"record_count"`
	FirstGeneratedAt  time.Time `json:"first_generated_at"`
	LastGeneratedAt   time.Time `json:"last_generated_at"`
	CreatedAt         time.Time `json:"created_at"`
	Compression       string    `json:"compression"`
	UncompressedBytes int       `json:"uncompressed_bytes"`
}

type SignedCompressedAgentLogBatch struct {
	Header            AgentLogBatchHeader `json:"header"`
	CompressedRecords []byte              `json:"compressed_records"`
	Signature         []byte              `json:"signature"`
}

func BuildAgentLogBatch(endpointID string, sequence uint64, records []AgentLogRecord, createdAt time.Time, key *ecdsa.PrivateKey) (SignedCompressedAgentLogBatch, error) {
	if endpointID == "" || sequence == 0 || len(records) == 0 || len(records) > maximumAgentLogRecords || createdAt.IsZero() || key == nil {
		return SignedCompressedAgentLogBatch{}, errors.New("Mossward agent-log batch input is invalid")
	}
	first, last := records[0].GeneratedAt, records[0].GeneratedAt
	for _, record := range records {
		if err := validateAgentLogRecord(record); err != nil {
			return SignedCompressedAgentLogBatch{}, err
		}
		if record.GeneratedAt.Before(first) {
			first = record.GeneratedAt
		}
		if record.GeneratedAt.After(last) {
			last = record.GeneratedAt
		}
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		return SignedCompressedAgentLogBatch{}, err
	}
	if len(encoded) > maximumExpandedLogBytes {
		return SignedCompressedAgentLogBatch{}, errors.New("Mossward agent-log batch exceeds the expanded-size limit")
	}
	compressed, err := compressAgentLogs(encoded)
	if err != nil {
		return SignedCompressedAgentLogBatch{}, err
	}
	if len(compressed) > maximumCompressedLogBytes {
		return SignedCompressedAgentLogBatch{}, errors.New("Mossward agent-log batch exceeds the compressed-size limit")
	}
	batchID, err := randomMessageID()
	if err != nil {
		return SignedCompressedAgentLogBatch{}, err
	}
	batch := SignedCompressedAgentLogBatch{Header: AgentLogBatchHeader{SchemaVersion: agentLogBatchSchemaVersion, BatchID: batchID,
		SourceEndpointID: endpointID, Source: agentLogSource, Sequence: sequence, RecordCount: len(records), FirstGeneratedAt: first.UTC(),
		LastGeneratedAt: last.UTC(), CreatedAt: createdAt.UTC(), Compression: agentLogCompression, UncompressedBytes: len(encoded)}, CompressedRecords: compressed}
	digest, err := agentLogBatchDigest(batch.Header, batch.CompressedRecords)
	if err != nil {
		return SignedCompressedAgentLogBatch{}, err
	}
	batch.Signature, err = ecdsa.SignASN1(rand.Reader, key, digest)
	return batch, err
}

func OpenAgentLogBatch(batch SignedCompressedAgentLogBatch, expectedEndpointID string, expectedSequence uint64, key *ecdsa.PublicKey) ([]AgentLogRecord, error) {
	if key == nil || !supportedAgentLogBatchVersion(batch.Header.SchemaVersion) || batch.Header.Source != agentLogSource || batch.Header.SourceEndpointID != expectedEndpointID ||
		batch.Header.BatchID == "" || expectedSequence == 0 || batch.Header.Sequence != expectedSequence || batch.Header.RecordCount < 1 || batch.Header.RecordCount > maximumAgentLogRecords ||
		batch.Header.CreatedAt.IsZero() || batch.Header.FirstGeneratedAt.IsZero() || batch.Header.LastGeneratedAt.Before(batch.Header.FirstGeneratedAt) ||
		batch.Header.Compression != agentLogCompression || batch.Header.UncompressedBytes < 1 || batch.Header.UncompressedBytes > maximumExpandedLogBytes ||
		len(batch.CompressedRecords) == 0 || len(batch.CompressedRecords) > maximumCompressedLogBytes {
		return nil, errors.New("Mossward agent-log batch envelope is invalid")
	}
	digest, err := agentLogBatchDigest(batch.Header, batch.CompressedRecords)
	if err != nil {
		return nil, err
	}
	if !ecdsa.VerifyASN1(key, digest, batch.Signature) {
		return nil, errors.New("Mossward agent-log batch signature verification failed")
	}
	expanded, err := expandAgentLogs(batch.CompressedRecords)
	if err != nil || len(expanded) != batch.Header.UncompressedBytes {
		return nil, errors.New("Mossward agent-log batch decompression failed")
	}
	var records []AgentLogRecord
	decoder := json.NewDecoder(bytes.NewReader(expanded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&records); err != nil || decoder.Decode(&struct{}{}) != io.EOF || len(records) != batch.Header.RecordCount {
		return nil, errors.New("Mossward agent-log batch records are invalid")
	}
	first, last := records[0].GeneratedAt, records[0].GeneratedAt
	for _, record := range records {
		if err := validateAgentLogRecordVersion(record, batch.Header.SchemaVersion); err != nil {
			return nil, err
		}
		if record.GeneratedAt.Before(first) {
			first = record.GeneratedAt
		}
		if record.GeneratedAt.After(last) {
			last = record.GeneratedAt
		}
	}
	if !first.Equal(batch.Header.FirstGeneratedAt) || !last.Equal(batch.Header.LastGeneratedAt) {
		return nil, errors.New("Mossward agent-log batch time provenance is invalid")
	}
	return records, nil
}

func supportedAgentLogBatchVersion(version int) bool {
	return version == legacyAgentLogBatchVersion || version == agentLogBatchSchemaVersion
}

func validateAgentLogRecordVersion(record AgentLogRecord, version int) error {
	if version == legacyAgentLogBatchVersion {
		return validateLegacyAgentLogRecord(record)
	}
	return validateAgentLogRecord(record)
}

func compressAgentLogs(encoded []byte) ([]byte, error) {
	var output bytes.Buffer
	writer, err := gzip.NewWriterLevel(&output, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(encoded); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func expandAgentLogs(compressed []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(io.LimitReader(reader, maximumExpandedLogBytes+1))
}

func agentLogBatchDigest(header AgentLogBatchHeader, compressed []byte) ([]byte, error) {
	encoded, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	_, _ = digest.Write(encoded)
	_, _ = digest.Write(compressed)
	return digest.Sum(nil), nil
}
