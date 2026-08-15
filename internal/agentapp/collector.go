package agentapp

import (
	"errors"
	"fmt"
	"sort"

	"mossward/internal/model"
)

// CollectorID identifies a built-in, read-only collection capability. It is
// deliberately not a command name or executable path.
type CollectorID = model.CollectorID

const (
	CollectorOperatingSystem   = model.CollectorOperatingSystem
	CollectorInstalledSoftware = model.CollectorInstalledSoftware
	CollectorListeningServices = model.CollectorListeningServices
	CollectorSecurityPosture   = model.CollectorSecurityPosture
	CollectorNetworkTelemetry  = model.CollectorNetworkTelemetry
)

var supportedCollectors = map[CollectorID]struct{}{
	CollectorOperatingSystem:   {},
	CollectorInstalledSoftware: {},
	CollectorListeningServices: {},
	CollectorSecurityPosture:   {},
	CollectorNetworkTelemetry:  {},
}

func effectiveCollectors(local, server []CollectorID) []CollectorID {
	locallyAllowed := make(map[CollectorID]struct{}, len(local))
	for _, collector := range local {
		locallyAllowed[collector] = struct{}{}
	}
	effective := make([]CollectorID, 0, len(server))
	for _, collector := range server {
		if _, ok := locallyAllowed[collector]; ok {
			effective = append(effective, collector)
		}
	}
	sort.Slice(effective, func(i, j int) bool { return effective[i] < effective[j] })
	return effective
}

func validateCollectorAllowlist(values []CollectorID) error {
	seen := make(map[CollectorID]struct{}, len(values))
	for _, collector := range values {
		if _, ok := supportedCollectors[collector]; !ok {
			return fmt.Errorf("endpoint-agent collector %q is unsupported", collector)
		}
		if _, duplicate := seen[collector]; duplicate {
			return errors.New("endpoint-agent collector allowlist contains a duplicate")
		}
		seen[collector] = struct{}{}
	}
	return nil
}

func supportedCollectorIDs() []CollectorID {
	collectors := make([]CollectorID, 0, len(supportedCollectors))
	for collector := range supportedCollectors {
		collectors = append(collectors, collector)
	}
	sort.Slice(collectors, func(i, j int) bool { return collectors[i] < collectors[j] })
	return collectors
}
