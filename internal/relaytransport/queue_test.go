package relaytransport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
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
	if err := queue.Acknowledge(frame.MessageID); err != nil {
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
