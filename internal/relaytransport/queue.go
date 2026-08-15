package relaytransport

import (
	"database/sql"
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
	queueSchemaVersion = 1
	queueFileMode      = 0o600
	queueDirectoryMode = 0o700
	maximumQueueAge    = 30 * 24 * time.Hour
)

var (
	ErrQueueDuplicate = errors.New("relay queue message already exists")
	ErrQueueEmpty     = errors.New("relay queue is empty")
	ErrQueueFull      = errors.New("relay queue capacity is exhausted")
)

type QueueLimits struct {
	MaxItems int
	MaxBytes int64
	MaxAge   time.Duration
}

type QueueStats struct {
	Items       int       `json:"items"`
	Bytes       int64     `json:"bytes"`
	OldestFrame time.Time `json:"oldest_frame,omitempty"`
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
	_, err = tx.Exec(`INSERT INTO relay_frames(message_id,frame_json,frame_size,created_at) VALUES(?,?,?,?)`,
		frame.MessageID, encoded, len(encoded), frame.CreatedAt.UTC().UnixNano())
	if err != nil {
		return fmt.Errorf("enqueue encrypted relay frame: %w", err)
	}
	return tx.Commit()
}

func (q *Queue) Peek(now time.Time) (Frame, error) {
	var frame Frame
	var encoded []byte
	err := q.db.QueryRow(`SELECT frame_json FROM relay_frames ORDER BY rowid LIMIT 1`).Scan(&encoded)
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

func (q *Queue) Acknowledge(messageID string) error {
	result, err := q.db.Exec(`DELETE FROM relay_frames WHERE message_id=?`, messageID)
	if err != nil {
		return fmt.Errorf("acknowledge relay queue frame: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read relay queue acknowledgement: %w", err)
	}
	if changed != 1 {
		return ErrQueueEmpty
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
	err := q.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(frame_size),0),MIN(created_at) FROM relay_frames`).Scan(&stats.Items, &stats.Bytes, &oldest)
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
	if version != queueSchemaVersion {
		return fmt.Errorf("unsupported relay queue schema %d", version)
	}
	return nil
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
