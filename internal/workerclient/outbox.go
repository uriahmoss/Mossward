package workerclient

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	outboxSchemaVersion = 1
	outboxKeyBytes      = 32
	outboxIdentityLimit = 200
)

var ErrOutboxFull = errors.New("scanner-worker outbox capacity is exhausted")
var ErrOutboxDuplicate = errors.New("scanner-worker outbox message already exists")
var ErrOutboxEmpty = errors.New("scanner-worker outbox is empty")

type OutboxKind string

const (
	OutboxEvidence   OutboxKind = "evidence"
	OutboxCompletion OutboxKind = "completion"
)

type OutboxLimits struct {
	MaxItems int
	MaxBytes int64
}

type OutboxMessage struct {
	ID        string
	Kind      OutboxKind
	Payload   []byte
	CreatedAt time.Time
}

type OutboxStats struct {
	Items int
	Bytes int64
}

type Outbox struct {
	db     *sql.DB
	aead   cipher.AEAD
	limits OutboxLimits
}

func OpenOutbox(databasePath, keyPath string, limits OutboxLimits) (*Outbox, error) {
	if limits.MaxItems < 1 || limits.MaxBytes < 1 {
		return nil, errors.New("scanner-worker outbox limits must be positive")
	}
	if err := preparePrivateWorkerPath(databasePath, "outbox"); err != nil {
		return nil, err
	}
	if err := preparePrivateWorkerPath(keyPath, "outbox key"); err != nil {
		return nil, err
	}
	key, err := loadOrCreateOutboxKey(keyPath)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize scanner-worker outbox encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize scanner-worker outbox authentication: %w", err)
	}
	dsn, err := workerSQLiteDSN(databasePath)
	if err != nil {
		return nil, err
	}
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open scanner-worker outbox: %w", err)
	}
	database.SetMaxOpenConns(1)
	outbox := &Outbox{db: database, aead: aead, limits: limits}
	if err := outbox.migrate(); err != nil {
		_ = database.Close()
		return nil, err
	}
	if err := os.Chmod(databasePath, privateWorkerFileMode); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("secure scanner-worker outbox: %w", err)
	}
	return outbox, nil
}

func (o *Outbox) migrate() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS outbox_metadata (schema_version INTEGER NOT NULL)`,
		`INSERT INTO outbox_metadata(schema_version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM outbox_metadata)`,
		`CREATE TABLE IF NOT EXISTS outbox_messages (id TEXT PRIMARY KEY,kind TEXT NOT NULL CHECK(kind IN ('evidence','completion')),ciphertext BLOB NOT NULL,nonce BLOB NOT NULL,plaintext_size INTEGER NOT NULL CHECK(plaintext_size>0),created_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS outbox_messages_fifo_idx ON outbox_messages(created_at,id)`,
	}
	for _, statement := range statements {
		if _, err := o.db.Exec(statement); err != nil {
			return fmt.Errorf("migrate scanner-worker outbox: %w", err)
		}
	}
	var version int
	if err := o.db.QueryRow(`SELECT schema_version FROM outbox_metadata LIMIT 1`).Scan(&version); err != nil {
		return fmt.Errorf("read scanner-worker outbox schema: %w", err)
	}
	if version != outboxSchemaVersion {
		return fmt.Errorf("unsupported scanner-worker outbox schema %d", version)
	}
	return nil
}

func (o *Outbox) Enqueue(message OutboxMessage) error {
	if err := validateOutboxMessage(message, o.limits); err != nil {
		return err
	}
	nonce := make([]byte, o.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("create scanner-worker outbox nonce: %w", err)
	}
	aad, err := outboxAAD(message.ID, message.Kind, message.CreatedAt)
	if err != nil {
		return err
	}
	ciphertext := o.aead.Seal(nil, nonce, message.Payload, aad)
	tx, err := o.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker outbox enqueue: %w", err)
	}
	defer tx.Rollback()
	var existing string
	err = tx.QueryRow(`SELECT id FROM outbox_messages WHERE id=?`, message.ID).Scan(&existing)
	if err == nil {
		return ErrOutboxDuplicate
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check scanner-worker outbox duplicate: %w", err)
	}
	var items int
	var bytesUsed int64
	if err := tx.QueryRow(`SELECT COUNT(*),COALESCE(SUM(plaintext_size),0) FROM outbox_messages`).Scan(&items, &bytesUsed); err != nil {
		return fmt.Errorf("read scanner-worker outbox capacity: %w", err)
	}
	if items >= o.limits.MaxItems || bytesUsed+int64(len(message.Payload)) > o.limits.MaxBytes {
		return ErrOutboxFull
	}
	_, err = tx.Exec(`INSERT INTO outbox_messages(id,kind,ciphertext,nonce,plaintext_size,created_at) VALUES(?,?,?,?,?,?)`, message.ID, message.Kind, ciphertext, nonce, len(message.Payload), formatWorkerTime(message.CreatedAt))
	if err != nil {
		return fmt.Errorf("enqueue scanner-worker outbox message: %w", err)
	}
	return tx.Commit()
}

func validateOutboxMessage(message OutboxMessage, limits OutboxLimits) error {
	if strings.TrimSpace(message.ID) == "" || len(message.ID) > outboxIdentityLimit || len(message.Payload) == 0 || int64(len(message.Payload)) > limits.MaxBytes || message.CreatedAt.IsZero() {
		return errors.New("scanner-worker outbox message is invalid")
	}
	if message.Kind != OutboxEvidence && message.Kind != OutboxCompletion {
		return errors.New("scanner-worker outbox message kind is invalid")
	}
	return nil
}

func (o *Outbox) Peek() (OutboxMessage, error) {
	var message OutboxMessage
	var ciphertext, nonce []byte
	var createdAt string
	err := o.db.QueryRow(`SELECT id,kind,ciphertext,nonce,created_at FROM outbox_messages ORDER BY created_at,id LIMIT 1`).Scan(&message.ID, &message.Kind, &ciphertext, &nonce, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return message, ErrOutboxEmpty
	}
	if err != nil {
		return message, fmt.Errorf("read scanner-worker outbox message: %w", err)
	}
	message.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return message, errors.New("scanner-worker outbox timestamp is invalid")
	}
	aad, err := outboxAAD(message.ID, message.Kind, message.CreatedAt)
	if err != nil {
		return message, err
	}
	message.Payload, err = o.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return message, errors.New("scanner-worker outbox integrity verification failed")
	}
	return message, nil
}

func (o *Outbox) Acknowledge(id string) error {
	result, err := o.db.Exec(`DELETE FROM outbox_messages WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("acknowledge scanner-worker outbox message: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read scanner-worker outbox acknowledgement: %w", err)
	}
	if changed != 1 {
		return ErrOutboxEmpty
	}
	return nil
}

func (o *Outbox) Stats() (OutboxStats, error) {
	var stats OutboxStats
	if err := o.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(plaintext_size),0) FROM outbox_messages`).Scan(&stats.Items, &stats.Bytes); err != nil {
		return stats, fmt.Errorf("read scanner-worker outbox statistics: %w", err)
	}
	return stats, nil
}

type OutboxSender func(context.Context, OutboxMessage) error

func (o *Outbox) ForwardPending(ctx context.Context, maximum int, send OutboxSender) (int, error) {
	if maximum < 1 || send == nil {
		return 0, errors.New("scanner-worker outbox forwarding configuration is invalid")
	}
	forwarded := 0
	for forwarded < maximum {
		if err := ctx.Err(); err != nil {
			return forwarded, err
		}
		message, err := o.Peek()
		if errors.Is(err, ErrOutboxEmpty) {
			return forwarded, nil
		}
		if err != nil {
			return forwarded, err
		}
		if err := send(ctx, message); err != nil {
			return forwarded, err
		}
		if err := o.Acknowledge(message.ID); err != nil {
			return forwarded, err
		}
		forwarded++
	}
	return forwarded, nil
}

func (o *Outbox) Close() error { return o.db.Close() }

func outboxAAD(id string, kind OutboxKind, createdAt time.Time) ([]byte, error) {
	encoded, err := json.Marshal(struct {
		ID        string     `json:"id"`
		Kind      OutboxKind `json:"kind"`
		CreatedAt string     `json:"created_at"`
	}{ID: id, Kind: kind, CreatedAt: formatWorkerTime(createdAt)})
	if err != nil {
		return nil, fmt.Errorf("encode scanner-worker outbox identity: %w", err)
	}
	return encoded, nil
}

func formatWorkerTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
