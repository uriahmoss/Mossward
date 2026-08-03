package workerclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestOutboxPersistsEncryptedMessagesUntilAcknowledged(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	databasePath := filepath.Join(directory, "outbox.db")
	keyPath := filepath.Join(directory, "outbox.key")
	outbox, err := OpenOutbox(databasePath, keyPath, OutboxLimits{MaxItems: 2, MaxBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	first := OutboxMessage{ID: "first", Kind: OutboxEvidence, Payload: []byte("four"), CreatedAt: now}
	second := OutboxMessage{ID: "second", Kind: OutboxCompletion, Payload: []byte("second"), CreatedAt: now.Add(time.Second)}
	if err := outbox.Enqueue(first); err != nil {
		t.Fatal(err)
	}
	if err := outbox.Enqueue(first); !errors.Is(err, ErrOutboxDuplicate) {
		t.Fatalf("duplicate outbox message was accepted: %v", err)
	}
	if err := outbox.Enqueue(second); err != nil {
		t.Fatal(err)
	}
	if err := outbox.Enqueue(OutboxMessage{ID: "full", Kind: OutboxEvidence, Payload: []byte("x"), CreatedAt: now.Add(2 * time.Second)}); !errors.Is(err, ErrOutboxFull) {
		t.Fatalf("bounded outbox exceeded capacity: %v", err)
	}
	var ciphertext []byte
	if err := outbox.db.QueryRow(`SELECT ciphertext FROM outbox_messages WHERE id=?`, first.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, first.Payload) {
		t.Fatal("outbox payload was stored in plaintext")
	}
	if err := outbox.Close(); err != nil {
		t.Fatal(err)
	}
	outbox, err = OpenOutbox(databasePath, keyPath, OutboxLimits{MaxItems: 2, MaxBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer outbox.Close()
	loaded, err := outbox.Peek()
	if err != nil || loaded.ID != first.ID || !bytes.Equal(loaded.Payload, first.Payload) {
		t.Fatalf("persisted outbox message did not decrypt: %#v %v", loaded, err)
	}
	if err := outbox.Acknowledge(first.ID); err != nil {
		t.Fatal(err)
	}
	loaded, err = outbox.Peek()
	if err != nil || loaded.ID != second.ID {
		t.Fatalf("outbox did not advance after acknowledgement: %#v %v", loaded, err)
	}
	stats, err := outbox.Stats()
	if err != nil || stats.Items != 1 || stats.Bytes != int64(len(second.Payload)) {
		t.Fatalf("unexpected outbox statistics: %#v %v", stats, err)
	}
	if runtime.GOOS != "windows" {
		assertPrivateWorkerFile(t, databasePath)
		assertPrivateWorkerFile(t, keyPath)
	}
}

func TestOutboxDetectsCiphertextTampering(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	outbox, err := OpenOutbox(filepath.Join(directory, "outbox.db"), filepath.Join(directory, "outbox.key"), OutboxLimits{MaxItems: 1, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer outbox.Close()
	message := OutboxMessage{ID: "tampered", Kind: OutboxEvidence, Payload: []byte("signed evidence"), CreatedAt: time.Now().UTC()}
	if err := outbox.Enqueue(message); err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.db.Exec(`UPDATE outbox_messages SET ciphertext=? WHERE id=?`, []byte("tampered"), message.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.Peek(); err == nil {
		t.Fatal("tampered outbox ciphertext was accepted")
	}
}

func TestOutboxForwardingRetainsUntilSuccessfulDelivery(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	outbox, err := OpenOutbox(filepath.Join(directory, "outbox.db"), filepath.Join(directory, "outbox.key"), OutboxLimits{MaxItems: 2, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer outbox.Close()
	message := OutboxMessage{ID: "delivery", Kind: OutboxCompletion, Payload: []byte("completion"), CreatedAt: time.Now().UTC()}
	if err := outbox.Enqueue(message); err != nil {
		t.Fatal(err)
	}
	temporaryFailure := errors.New("server unavailable")
	forwarded, err := outbox.ForwardPending(context.Background(), 1, func(context.Context, OutboxMessage) error {
		return temporaryFailure
	})
	if forwarded != 0 || !errors.Is(err, temporaryFailure) {
		t.Fatalf("temporary delivery failure was not retained: forwarded=%d err=%v", forwarded, err)
	}
	if stats, err := outbox.Stats(); err != nil || stats.Items != 1 {
		t.Fatalf("failed delivery left unexpected outbox state: %#v %v", stats, err)
	}
	forwarded, err = outbox.ForwardPending(context.Background(), 1, func(_ context.Context, delivered OutboxMessage) error {
		if delivered.ID != message.ID || !bytes.Equal(delivered.Payload, message.Payload) {
			t.Fatalf("unexpected delivered outbox message: %#v", delivered)
		}
		return nil
	})
	if err != nil || forwarded != 1 {
		t.Fatalf("successful outbox delivery failed: forwarded=%d err=%v", forwarded, err)
	}
	if _, err := outbox.Peek(); !errors.Is(err, ErrOutboxEmpty) {
		t.Fatalf("acknowledged outbox message remained queued: %v", err)
	}
}

func assertPrivateWorkerFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != privateWorkerFileMode {
		t.Fatalf("%s permissions = %o", filepath.Base(path), info.Mode().Perm())
	}
}
