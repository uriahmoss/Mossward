package store

import (
	"errors"
	"time"

	"mossward/internal/model"
)

var ErrNotFound = errors.New("scan not found")

type Repository interface {
	Save(model.Scan) error
	Get(string) (model.Scan, error)
	List() ([]model.Scan, error)
	ReconcileInterrupted() error
	UpsertCVEs([]model.CVERecord) error
	MatchObservation(model.ServiceObservation) ([]model.CVEMatch, error)
	ListCriticalNews(int) ([]model.CVENewsItem, error)
	FeedStatus() (model.FeedStatus, error)
	RecordFeedStart(string, time.Time) error
	RecordFeedResult(string, time.Time, int, string) error
	Close() error
}
