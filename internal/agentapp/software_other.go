//go:build !linux && !windows

package agentapp

import (
	"errors"

	"mossward/internal/model"
)

func platformSoftwareInventory() ([]model.InstalledSoftware, error) {
	return nil, errors.New("software inventory is supported only on Linux and Windows")
}
