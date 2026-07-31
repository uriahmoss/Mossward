package store

import (
	"errors"

	"mossward/internal/model"
)

var ErrNotFound = errors.New("scan not found")

type Repository interface {
	Save(model.Scan) error
	Get(string) (model.Scan, error)
	List() ([]model.Scan, error)
	ReconcileInterrupted() error
	Close() error
}
