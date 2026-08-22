package relaytransport

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	queueSchemaVersion = 3
	queueFileMode      = 0o600
	queueDirectoryMode = 0o700
	maximumQueueAge    = 30 * 24 * time.Hour
	deliveryTokenBytes = 16
)

type QueuePriority int

const (
	QueuePriorityRoutine  QueuePriority = 100
	QueuePriorityElevated QueuePriority = 200
	QueuePriorityCritical QueuePriority = 300
)

var (
	ErrQueueDuplicate   = errors.New("relay queue message already exists")
	ErrQueueEmpty       = errors.New("relay queue is empty")
	ErrQueueFull        = errors.New("relay queue capacity is exhausted")
	ErrQueueAckRejected = errors.New("relay queue acknowledgement was rejected")
)

type Delivery struct {
	Frame      Frame
	Token      string
	Attempt    int
	LeaseUntil time.Time
}

type QueueLimits struct {
	MaxItems int
	MaxBytes int64
	MaxAge   time.Duration
}

type QueueStats struct {
	Items         int       `json:"items"`
	Bytes         int64     `json:"bytes"`
	RoutineItems  int       `json:"routine_items"`
	ElevatedItems int       `json:"elevated_items"`
	CriticalItems int       `json:"critical_items"`
	LeasedItems   int       `json:"leased_items"`
	OldestFrame   time.Time `json:"oldest_frame,omitempty"`
}

type Queue struct {
	db     *sql.DB
	limits QueueLimits
}

func OpenQueue(path string, limits QueueLimits) (*Queue, error) {
	if err := validateQueueLimits(limits); err != nil {
		return nil, err
	}
	if err := prepareQueuePath(path); err != nil {
		return nil, err
	}
	dsn, err := queueDSN(path)
	if err != nil {
		return nil, err
	}
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open relay queue: %w", err)
	}
	database.SetMaxOpenConns(1)
	queue := &Queue{db: database, limits: limits}
	if err := queue.migrate(); err != nil {
		_ = database.Close()
		return nil, err
	}
	if err := os.Chmod(path, queueFileMode); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("secure relay queue: %w", err)
	}
	return queue, nil
}

func (q *Queue) Enqueue(frame Frame, now time.Time) error {
	if err := ValidateFrame(frame, now); err != nil {
		return err
	}
	if frame.CreatedAt.Before(now.Add(-q.limits.MaxAge)) {
		return errors.New("relay frame exceeds the queue retention limit")
	}
	encoded, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("encode encrypted relay frame: %w", err)
	}
	if int64(len(encoded)) > q.limits.MaxBytes {
		return ErrQueueFull
	}
	tx, err := q.db.Begin()
	if err != nil {
		return fmt.Errorf("begin relay queue enqueue: %w", err)
	}
	defer tx.Rollback()
	var exists int
	err = tx.QueryRow(`SELECT 1 FROM relay_frames WHERE message_id=?`, frame.MessageID).Scan(&exists)
	if err == nil {
		return ErrQueueDuplicate
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check relay queue duplicate: %w", err)
	}
	var items int
	var bytesUsed int64
	if err := tx.QueryRow(`SELECT COUNT(*),COALESCE(SUM(frame_size),0) FROM relay_frames`).Scan(&items, &bytesUsed); err != nil {
		return fmt.Errorf("read relay queue capacity: %w", err)
	}
	if items >= q.limits.MaxItems || bytesUsed+int64(len(encoded)) > q.limits.MaxBytes {
		return ErrQueueFull
	}
	_, err = tx.Exec(`INSERT INTO relay_frames(message_id,frame_json,frame_size,created_at,priority) VALUES(?,?,?,?,?)`,
		frame.MessageID, encoded, len(encoded), frame.CreatedAt.UTC().UnixNano(), priorityForFrame(frame))
	if err != nil {
		return fmt.Errorf("enqueue encrypted relay frame: %w", err)
	}
	return tx.Commit()
}

func (q *Queue) Peek(now time.Time) (Frame, error) {
	var frame Frame
	var encoded []byte
	err := q.db.QueryRow(`SELECT frame_json FROM relay_frames ORDER BY priority DESC,rowid LIMIT 1`).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return frame, ErrQueueEmpty
	}
	if err != nil {
		return frame, fmt.Errorf("read relay queue frame: %w", err)
	}
	if err := json.Unmarshal(encoded, &frame); err != nil {
		return frame, errors.New("stored relay frame is invalid")
	}
	if err := ValidateFrame(frame, now); err != nil {
		return frame, fmt.Errorf("validate stored relay frame: %w", err)
	}
	return frame, nil
}

func (q *Queue) Claim(now time.Time, leaseDuration time.Duration) (Delivery, error) {
	if leaseDuration <= 0 {
		return Delivery{}, errors.New("relay delivery lease duration must be positive")
	}
	token, err := newDeliveryToken()
	if err != nil {
		return Delivery{}, err
	}
	tx, err := q.db.Begin()
	if err != nil {
		return Delivery{}, fmt.Errorf("begin relay delivery claim: %w", err)
	}
	defer tx.Rollback()
	var delivery Delivery
	var encoded []byte
	err = tx.QueryRow(`SELECT message_id,frame_json,attempt_count FROM relay_frames
		WHERE delivery_token IS NULL OR lease_until<=? ORDER BY priority DESC,rowid LIMIT 1`, now.UTC().UnixNano()).
		Scan(&delivery.Frame.MessageID, &encoded, &delivery.Attempt)
	if errors.Is(err, sql.ErrNoRows) {
		return Delivery{}, ErrQueueEmpty
	}
	if err != nil {
		return Delivery{}, fmt.Errorf("select relay delivery: %w", err)
	}
	delivery.Attempt++
	delivery.Token = token
	delivery.LeaseUntil = now.Add(leaseDuration).UTC()
	result, err := tx.Exec(`UPDATE relay_frames SET delivery_token=?,lease_until=?,attempt_count=?
		WHERE message_id=? AND (delivery_token IS NULL OR lease_until<=?)`, delivery.Token, delivery.LeaseUntil.UnixNano(),
		delivery.Attempt, delivery.Frame.MessageID, now.UTC().UnixNano())
	if err != nil {
		return Delivery{}, fmt.Errorf("claim relay delivery: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return Delivery{}, ErrQueueEmpty
	}
	if err := json.Unmarshal(encoded, &delivery.Frame); err != nil {
		return Delivery{}, errors.New("stored relay frame is invalid")
	}
	if err := ValidateFrame(delivery.Frame, now); err != nil {
		return Delivery{}, fmt.Errorf("validate claimed relay frame: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Delivery{}, fmt.Errorf("commit relay delivery claim: %w", err)
	}
	return delivery, nil
}

func (q *Queue) Acknowledge(messageID, token string) error {
	if strings.TrimSpace(messageID) == "" || strings.TrimSpace(token) == "" {
		return ErrQueueAckRejected
	}
	result, err := q.db.Exec(`DELETE FROM relay_frames WHERE message_id=? AND delivery_token=?`, messageID, token)
	if err != nil {
		return fmt.Errorf("acknowledge relay queue frame: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read relay queue acknowledgement: %w", err)
	}
	if changed != 1 {
		return ErrQueueAckRejected
	}
	return nil
}

func (q *Queue) Release(messageID, token string) error {
	result, err := q.db.Exec(`UPDATE relay_frames SET delivery_token=NULL,lease_until=NULL
		WHERE message_id=? AND delivery_token=?`, messageID, token)
	if err != nil {
		return fmt.Errorf("release relay queue delivery: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrQueueAckRejected
	}
	return nil
}

func (q *Queue) PurgeExpired(now time.Time) (int64, error) {
	cutoff := now.Add(-q.limits.MaxAge).UTC().UnixNano()
	result, err := q.db.Exec(`DELETE FROM relay_frames WHERE created_at<?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("purge expired relay frames: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read expired relay frame count: %w", err)
	}
	return count, nil
}

func (q *Queue) Stats() (QueueStats, error) {
	var stats QueueStats
	var oldest sql.NullInt64
	err := q.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(frame_size),0),
		COALESCE(SUM(CASE WHEN priority=? THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN priority=? THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN priority=? THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN delivery_token IS NOT NULL THEN 1 ELSE 0 END),0),MIN(created_at) FROM relay_frames`,
		QueuePriorityRoutine, QueuePriorityElevated, QueuePriorityCritical).Scan(&stats.Items, &stats.Bytes, &stats.RoutineItems, &stats.ElevatedItems, &stats.CriticalItems, &stats.LeasedItems, &oldest)
	if err != nil {
		return stats, fmt.Errorf("read relay queue statistics: %w", err)
	}
	if oldest.Valid {
		stats.OldestFrame = time.Unix(0, oldest.Int64).UTC()
	}
	return stats, nil
}

func (q *Queue) Close() error { return q.db.Close() }

func (q *Queue) migrate() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS relay_queue_metadata (schema_version INTEGER NOT NULL)`,
		`INSERT INTO relay_queue_metadata(schema_version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM relay_queue_metadata)`,
		`CREATE TABLE IF NOT EXISTS relay_frames (message_id TEXT PRIMARY KEY,frame_json BLOB NOT NULL,frame_size INTEGER NOT NULL CHECK(frame_size>0),created_at INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS relay_frames_fifo_idx ON relay_frames(created_at,message_id)`,
	}
	for _, statement := range statements {
		if _, err := q.db.Exec(statement); err != nil {
			return fmt.Errorf("migrate relay queue: %w", err)
		}
	}
	var version int
	if err := q.db.QueryRow(`SELECT schema_version FROM relay_queue_metadata LIMIT 1`).Scan(&version); err != nil {
		return fmt.Errorf("read relay queue schema: %w", err)
	}
	if version > queueSchemaVersion {
		return fmt.Errorf("unsupported relay queue schema %d", version)
	}
	if version == 1 {
		if err := q.migratePriorityQueue(version); err != nil {
			return err
		}
		version = 2
	}
	if version == 2 {
		if err := q.migrateDeliveryQueue(); err != nil {
			return err
		}
	}
	return nil
}

func (q *Queue) migrateDeliveryQueue() error {
	tx, err := q.db.Begin()
	if err != nil {
		return fmt.Errorf("begin relay delivery migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE relay_frames ADD COLUMN delivery_token TEXT`,
		`ALTER TABLE relay_frames ADD COLUMN lease_until INTEGER`,
		`ALTER TABLE relay_frames ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0`,
		`CREATE INDEX relay_frames_delivery_idx ON relay_frames(priority DESC,lease_until,created_at,message_id)`,
		`UPDATE relay_queue_metadata SET schema_version=3`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("migrate relay delivery queue: %w", err)
		}
	}
	return tx.Commit()
}

func (q *Queue) migratePriorityQueue(version int) error {
	if version != 1 {
		return fmt.Errorf("unsupported relay queue schema %d", version)
	}
	tx, err := q.db.Begin()
	if err != nil {
		return fmt.Errorf("begin relay priority-queue migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE relay_frames ADD COLUMN priority INTEGER NOT NULL DEFAULT 100`); err != nil {
		return fmt.Errorf("migrate relay priority queue: %w", err)
	}
	rows, err := tx.Query(`SELECT message_id,frame_json FROM relay_frames`)
	if err != nil {
		return fmt.Errorf("read legacy relay priorities: %w", err)
	}
	type legacyPriority struct {
		messageID string
		priority  QueuePriority
	}
	priorities := []legacyPriority{}
	for rows.Next() {
		var item legacyPriority
		var encoded []byte
		if err := rows.Scan(&item.messageID, &encoded); err != nil {
			rows.Close()
			return fmt.Errorf("scan legacy relay priority: %w", err)
		}
		var frame Frame
		if json.Unmarshal(encoded, &frame) == nil {
			item.priority = priorityForFrame(frame)
		} else {
			item.priority = QueuePriorityRoutine
		}
		priorities = append(priorities, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read legacy relay priority rows: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy relay priority rows: %w", err)
	}
	for _, item := range priorities {
		if _, err := tx.Exec(`UPDATE relay_frames SET priority=? WHERE message_id=?`, item.priority, item.messageID); err != nil {
			return fmt.Errorf("update legacy relay priority: %w", err)
		}
	}
	for _, statement := range []string{`CREATE INDEX relay_frames_priority_idx ON relay_frames(priority DESC,created_at,message_id)`, `UPDATE relay_queue_metadata SET schema_version=2`} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("finish relay priority-queue migration: %w", err)
		}
	}
	return tx.Commit()
}

func priorityForFrame(frame Frame) QueuePriority {
	switch frame.Kind {
	case MessageIntegrityAlert, MessageTamperAlert:
		return QueuePriorityCritical
	case MessageAgentCheckIn, MessageServerReply:
		return QueuePriorityElevated
	default:
		return QueuePriorityRoutine
	}
}

func newDeliveryToken() (string, error) {
	buffer := make([]byte, deliveryTokenBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("create relay delivery token: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

func validateQueueLimits(limits QueueLimits) error {
	if limits.MaxItems < 1 || limits.MaxBytes < 1 || limits.MaxAge <= 0 || limits.MaxAge > maximumQueueAge {
		return errors.New("relay queue limits are invalid")
	}
	return nil
}

func prepareQueuePath(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("relay queue path is required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, queueDirectoryMode); err != nil {
		return fmt.Errorf("create relay queue directory: %w", err)
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect relay queue directory: %w", err)
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("relay queue directory cannot be a symbolic link")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("relay queue cannot be a symbolic link")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return errors.New("relay queue permissions are too broad")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect relay queue: %w", err)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	if directoryInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("relay queue directory permissions are too broad")
	}
	return nil
}

func queueDSN(path string) (string, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve relay queue path: %w", err)
	}
	slashPath := filepath.ToSlash(absolutePath)
	if filepath.VolumeName(absolutePath) != "" && !strings.HasPrefix(slashPath, "/") {
		slashPath = "/" + slashPath
	}
	return (&url.URL{Scheme: "file", Path: slashPath,
		RawQuery: "_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)"}).String(), nil
}
