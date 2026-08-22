package relaytransport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQueuePersistsOnlyEncryptedBoundedFrames(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	frame := testSealedFrame(t, now, "00112233445566778899aabbccddeeff", []byte("sensitive agent log"))
	encoded, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "relay", "queue.db")
	queue, err := OpenQueue(path, QueueLimits{MaxItems: 1, MaxBytes: int64(len(encoded)), MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(frame, now); err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(frame, now); !errors.Is(err, ErrQueueDuplicate) {
		t.Fatalf("duplicate frame result = %v", err)
	}
	second := testSealedFrame(t, now, "ffeeddccbbaa99887766554433221100", []byte("another log"))
	if err := queue.Enqueue(second, now); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("queue capacity result = %v", err)
	}
	var stored []byte
	if err := queue.db.QueryRow(`SELECT frame_json FROM relay_frames WHERE message_id=?`, frame.MessageID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("sensitive agent log")) {
		t.Fatal("relay queue stored plaintext message content")
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
	queue, err = OpenQueue(path, QueueLimits{MaxItems: 1, MaxBytes: int64(len(encoded)), MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	loaded, err := queue.Peek(now)
	if err != nil || loaded.MessageID != frame.MessageID || !bytes.Equal(loaded.Ciphertext, frame.Ciphertext) {
		t.Fatalf("persisted frame = %#v, error = %v", loaded, err)
	}
	stats, err := queue.Stats()
	if err != nil || stats.Items != 1 || stats.Bytes != int64(len(encoded)) || stats.OldestFrame.IsZero() {
		t.Fatalf("queue stats = %#v, error = %v", stats, err)
	}
	delivery, err := queue.Claim(now, time.Minute)
	if err != nil || delivery.Frame.MessageID != frame.MessageID {
		t.Fatalf("claimed frame = %#v, error = %v", delivery, err)
	}
	if err := queue.Acknowledge(frame.MessageID, delivery.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Peek(now); !errors.Is(err, ErrQueueEmpty) {
		t.Fatalf("acknowledged frame remained queued: %v", err)
	}
}

func TestQueueRejectsExpiredFramesAndReportsPurges(t *testing.T) {
	now := time.Now().UTC()
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "relay", "queue.db"), QueueLimits{MaxItems: 2, MaxBytes: 1 << 20, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	expired := testSealedFrame(t, now.Add(-2*time.Hour), "00112233445566778899aabbccddeeff", []byte("expired"))
	if err := queue.Enqueue(expired, now); err == nil {
		t.Fatal("expired relay frame was accepted")
	}
	current := testSealedFrame(t, now, "ffeeddccbbaa99887766554433221100", []byte("current"))
	if err := queue.Enqueue(current, now); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.db.Exec(`UPDATE relay_frames SET created_at=? WHERE message_id=?`, now.Add(-2*time.Hour).UnixNano(), current.MessageID); err != nil {
		t.Fatal(err)
	}
	purged, err := queue.PurgeExpired(now)
	if err != nil || purged != 1 {
		t.Fatalf("purged frames = %d, error = %v", purged, err)
	}
}

func TestQueueDeliversSecurityAlertsBeforeRoutineTelemetry(t *testing.T) {
	now := time.Now().UTC()
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "relay", "queue.db"), QueueLimits{MaxItems: 4, MaxBytes: 8 << 20, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	frames := []Frame{
		testSealedFrameKind(t, now, "00000000000000000000000000000001", MessageAgentLogBatch),
		testSealedFrameKind(t, now, "00000000000000000000000000000002", MessageTamperAlert),
		testSealedFrameKind(t, now, "00000000000000000000000000000003", MessageAgentCheckIn),
		testSealedFrameKind(t, now, "00000000000000000000000000000004", MessageIntegrityAlert),
	}
	for _, frame := range frames {
		if err := queue.Enqueue(frame, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, expected := range []MessageKind{MessageTamperAlert, MessageIntegrityAlert, MessageAgentCheckIn, MessageAgentLogBatch} {
		delivery, err := queue.Claim(now, time.Minute)
		if err != nil || delivery.Frame.Kind != expected {
			t.Fatalf("priority dequeue = %s, expected %s, error = %v", delivery.Frame.Kind, expected, err)
		}
		if err := queue.Acknowledge(delivery.Frame.MessageID, delivery.Token); err != nil {
			t.Fatal(err)
		}
	}
}

func TestQueueRequiresMatchingAcknowledgementAndResumesExpiredDelivery(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "relay", "queue.db")
	limits := QueueLimits{MaxItems: 2, MaxBytes: 1 << 20, MaxAge: time.Hour}
	queue, err := OpenQueue(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	frame := testSealedFrame(t, now, "00112233445566778899aabbccddeeff", []byte("resume"))
	if err := queue.Enqueue(frame, now); err != nil {
		t.Fatal(err)
	}
	first, err := queue.Claim(now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Acknowledge(frame.MessageID, "incorrect-token"); !errors.Is(err, ErrQueueAckRejected) {
		t.Fatalf("incorrect acknowledgement result = %v", err)
	}
	if _, err := queue.Claim(now.Add(30*time.Second), time.Minute); !errors.Is(err, ErrQueueEmpty) {
		t.Fatalf("active lease was claimed again: %v", err)
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
	queue, err = OpenQueue(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	resumed, err := queue.Claim(now.Add(2*time.Minute), time.Minute)
	if err != nil || resumed.Frame.MessageID != frame.MessageID || resumed.Attempt != 2 || resumed.Token == first.Token {
		t.Fatalf("resumed delivery = %#v, error = %v", resumed, err)
	}
	if err := queue.Acknowledge(frame.MessageID, resumed.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Peek(now); !errors.Is(err, ErrQueueEmpty) {
		t.Fatalf("acknowledged frame remained: %v", err)
	}
}

func TestQueueReleaseMakesDeliveryImmediatelyAvailable(t *testing.T) {
	now := time.Now().UTC()
	queue, err := OpenQueue(filepath.Join(t.TempDir(), "relay", "queue.db"), QueueLimits{MaxItems: 1, MaxBytes: 1 << 20, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	frame := testSealedFrame(t, now, "00112233445566778899aabbccddeeff", []byte("retry"))
	if err := queue.Enqueue(frame, now); err != nil {
		t.Fatal(err)
	}
	delivery, err := queue.Claim(now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Release(frame.MessageID, delivery.Token); err != nil {
		t.Fatal(err)
	}
	retry, err := queue.Claim(now, time.Minute)
	if err != nil || retry.Attempt != 2 {
		t.Fatalf("released delivery retry = %#v, error = %v", retry, err)
	}
}

func TestQueueMigratesLegacyFramesWithoutDataLoss(t *testing.T) {
	now := time.Now().UTC()
	directory := filepath.Join(t.TempDir(), "relay")
	if err := os.Mkdir(directory, queueDirectoryMode); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "queue.db")
	dsn, err := queueDSN(path)
	if err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	frame := testSealedFrameKind(t, now, "00112233445566778899aabbccddeeff", MessageTamperAlert)
	encoded, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE relay_queue_metadata (schema_version INTEGER NOT NULL)`,
		`INSERT INTO relay_queue_metadata(schema_version) VALUES(1)`,
		`CREATE TABLE relay_frames (message_id TEXT PRIMARY KEY,frame_json BLOB NOT NULL,frame_size INTEGER NOT NULL CHECK(frame_size>0),created_at INTEGER NOT NULL)`,
	} {
		if _, err := database.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.Exec(`INSERT INTO relay_frames(message_id,frame_json,frame_size,created_at) VALUES(?,?,?,?)`, frame.MessageID, encoded, len(encoded), now.UnixNano()); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, queueFileMode); err != nil {
		t.Fatal(err)
	}
	queue, err := OpenQueue(path, QueueLimits{MaxItems: 2, MaxBytes: 1 << 20, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	loaded, err := queue.Peek(now)
	if err != nil || loaded.MessageID != frame.MessageID {
		t.Fatalf("migrated relay frame = %#v, error = %v", loaded, err)
	}
	stats, err := queue.Stats()
	if err != nil || stats.RoutineItems != 0 || stats.CriticalItems != 1 {
		t.Fatalf("migrated queue stats = %#v, error = %v", stats, err)
	}
}

func testSealedFrame(t *testing.T, createdAt time.Time, messageID string, plaintext []byte) Frame {
	t.Helper()
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientKey, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	frame := Frame{MessageID: messageID, Kind: MessageAgentLogBatch, DownstreamEndpointID: "endpoint",
		SenderID: "endpoint", RecipientID: "server", Sequence: 1, CreatedAt: createdAt}
	sealed, err := Seal(frame, plaintext, signingKey, recipientKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func testSealedFrameKind(t *testing.T, createdAt time.Time, messageID string, kind MessageKind) Frame {
	t.Helper()
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientKey, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	frame := Frame{MessageID: messageID, Kind: kind, DownstreamEndpointID: "endpoint",
		SenderID: "endpoint", RecipientID: "server", Sequence: 1, CreatedAt: createdAt}
	sealed, err := Seal(frame, []byte("encrypted telemetry"), signingKey, recipientKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}
