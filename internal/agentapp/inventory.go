package agentapp

import (
	"errors"
	"runtime"
	"slices"
	"time"

	"mossward/internal/model"
)

func collectOSInventory(allowlist []CollectorID, now time.Time) (*model.EndpointOSInventory, error) {
	if !slices.Contains(allowlist, CollectorOperatingSystem) {
		return nil, nil
	}
	inventory, err := platformOSInventory()
	if err != nil {
		return nil, err
	}
	inventory.Architecture = runtime.GOARCH
	inventory.CollectedAt = now
	return &inventory, nil
}

func validateOSInventory(inventory *model.EndpointOSInventory) error {
	if inventory == nil {
		return nil
	}
	if inventory.Family != "linux" && inventory.Family != "windows" {
		return errors.New("OS inventory family is unsupported")
	}
	if inventory.Name == "" || inventory.Version == "" || inventory.Kernel == "" || inventory.Architecture == "" {
		return errors.New("OS inventory is incomplete")
	}
	if len(inventory.Patches) > 10000 {
		return errors.New("OS patch inventory exceeds limit")
	}
	seen := map[string]bool{}
	for _, patch := range inventory.Patches {
		if patch.ID == "" || len(patch.ID) > 200 || len(patch.Description) > 500 || seen[patch.ID] {
			return errors.New("OS patch inventory is invalid")
		}
		seen[patch.ID] = true
	}
	return nil
}

func collectSoftwareInventory(allowlist []CollectorID, now time.Time) (*model.EndpointSoftwareInventory, error) {
	if !slices.Contains(allowlist, CollectorInstalledSoftware) {
		return nil, nil
	}
	items, err := platformSoftwareInventory()
	if err != nil {
		return nil, err
	}
	return &model.EndpointSoftwareInventory{Items: items, CollectedAt: now}, nil
}
