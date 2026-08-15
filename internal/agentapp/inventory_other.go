//go:build !linux && !windows

package agentapp

import (
	"errors"
	"mossward/internal/model"
)

func platformOSInventory() (model.EndpointOSInventory, error) {
	return model.EndpointOSInventory{}, errors.New("endpoint OS inventory is supported only on Linux and Windows")
}
