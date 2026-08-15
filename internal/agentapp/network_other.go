//go:build !linux && !windows

package agentapp

import (
	"errors"
	"mossward/internal/model"
)

func platformNetworkInventory() ([]model.NetworkConnection, error) {
	return nil, errors.New("network metadata collection is supported only on Linux and Windows")
}
