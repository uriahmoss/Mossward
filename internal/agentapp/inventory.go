package agentapp

import (
	"errors"
	"runtime"
	"slices"
	"time"

	"mossward/internal/model"
	"mossward/internal/networkpolicy"
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

func collectListeningInventory(allowlist []CollectorID, now time.Time) (*model.EndpointListeningInventory, error) {
	if !slices.Contains(allowlist, CollectorListeningServices) {
		return nil, nil
	}
	services, err := platformListeningInventory()
	if err != nil {
		return nil, err
	}
	return &model.EndpointListeningInventory{Services: services, CollectedAt: now}, nil
}

func collectPostureInventory(allowlist []CollectorID, now time.Time) (*model.EndpointPostureInventory, error) {
	if !slices.Contains(allowlist, CollectorSecurityPosture) {
		return nil, nil
	}
	evidence, err := platformPostureEvidence()
	if err != nil {
		return nil, err
	}
	return &model.EndpointPostureInventory{Evidence: evidence, CollectedAt: now}, nil
}

func collectNetworkInventory(allowlist []CollectorID, now time.Time, exclusions ...model.NetworkTelemetryExclusions) (*model.EndpointNetworkInventory, error) {
	if !slices.Contains(allowlist, CollectorNetworkTelemetry) {
		return nil, nil
	}
	connections, err := platformNetworkInventory()
	if err != nil {
		return nil, err
	}
	contexts := platformNetworkNameContext()
	for index := range connections {
		context, ok := contexts[connections[index].RemoteAddress]
		if !ok {
			continue
		}
		connections[index].RemoteHostname = context.hostname
		connections[index].HostnameSource = context.source
	}
	return &model.EndpointNetworkInventory{Connections: networkpolicy.Filter(connections, exclusions...), CollectedAt: now}, nil
}

type networkNameContext struct{ hostname, source string }
