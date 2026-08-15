//go:build !linux && !windows

package agentapp

import (
	"errors"
	"mossward/internal/model"
)

func platformListeningInventory() ([]model.ListeningService, error) {
	return nil, errors.New("listening-service inventory is supported only on Linux and Windows")
}
