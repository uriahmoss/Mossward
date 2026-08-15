package networkpolicy

import (
	"errors"
	"net/netip"
	"strings"

	"mossward/internal/model"
)

const (
	maximumExclusions = 100
	maximumValueBytes = 500
)

func Normalize(policy model.NetworkTelemetryExclusions) (model.NetworkTelemetryExclusions, error) {
	applications, err := normalizeList(policy.Applications, true)
	if err != nil {
		return policy, err
	}
	destinations, err := normalizeList(policy.Destinations, false)
	if err != nil {
		return policy, err
	}
	return model.NetworkTelemetryExclusions{Applications: applications, Destinations: destinations}, nil
}

func Filter(connections []model.NetworkConnection, policies ...model.NetworkTelemetryExclusions) []model.NetworkConnection {
	filtered := make([]model.NetworkConnection, 0, len(connections))
	for _, connection := range connections {
		if excluded(connection, policies) {
			continue
		}
		filtered = append(filtered, connection)
	}
	return filtered
}

func normalizeList(values []model.NetworkTelemetryExclusion, application bool) ([]model.NetworkTelemetryExclusion, error) {
	if len(values) > maximumExclusions {
		return nil, errors.New("network telemetry exclusion list exceeds 100 entries")
	}
	result := make([]model.NetworkTelemetryExclusion, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		normalized, err := normalize(value, application)
		if err != nil {
			return nil, err
		}
		key := string(normalized.Kind) + "\x00" + normalized.Value
		if seen[key] {
			return nil, errors.New("network telemetry exclusions contain a duplicate")
		}
		seen[key] = true
		result = append(result, normalized)
	}
	return result, nil
}

func normalize(value model.NetworkTelemetryExclusion, application bool) (model.NetworkTelemetryExclusion, error) {
	value.Value = strings.TrimSpace(value.Value)
	if value.Value == "" || len(value.Value) > maximumValueBytes {
		return value, errors.New("network telemetry exclusion value is invalid")
	}
	if application {
		if value.Kind != model.NetworkExcludeProcessName && value.Kind != model.NetworkExcludeExecutable {
			return value, errors.New("application exclusion kind must be process_name or executable")
		}
		return value, nil
	}
	switch value.Kind {
	case model.NetworkExcludeIP:
		address, err := netip.ParseAddr(value.Value)
		if err != nil {
			return value, errors.New("IP exclusion is invalid")
		}
		value.Value = address.String()
	case model.NetworkExcludeCIDR:
		prefix, err := netip.ParsePrefix(value.Value)
		if err != nil {
			return value, errors.New("CIDR exclusion is invalid")
		}
		value.Value = prefix.Masked().String()
	case model.NetworkExcludeHostname:
		value.Value = strings.ToLower(strings.TrimSuffix(value.Value, "."))
		if !validHostname(value.Value) {
			return value, errors.New("hostname exclusion must be exact")
		}
	default:
		return value, errors.New("destination exclusion kind must be ip, cidr, or hostname")
	}
	return value, nil
}

func validHostname(value string) bool {
	if len(value) < 1 || len(value) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func excluded(connection model.NetworkConnection, policies []model.NetworkTelemetryExclusions) bool {
	for _, policy := range policies {
		for _, exclusion := range policy.Applications {
			candidate := connection.ProcessName
			if exclusion.Kind == model.NetworkExcludeExecutable {
				candidate = connection.Executable
			}
			if strings.EqualFold(candidate, exclusion.Value) {
				return true
			}
		}
		for _, exclusion := range policy.Destinations {
			if destinationMatches(connection, exclusion) {
				return true
			}
		}
	}
	return false
}

func destinationMatches(connection model.NetworkConnection, exclusion model.NetworkTelemetryExclusion) bool {
	switch exclusion.Kind {
	case model.NetworkExcludeIP:
		return connection.RemoteAddress == exclusion.Value
	case model.NetworkExcludeHostname:
		return strings.EqualFold(strings.TrimSuffix(connection.RemoteHostname, "."), exclusion.Value)
	case model.NetworkExcludeCIDR:
		prefix, prefixErr := netip.ParsePrefix(exclusion.Value)
		address, addressErr := netip.ParseAddr(connection.RemoteAddress)
		return prefixErr == nil && addressErr == nil && prefix.Contains(address)
	default:
		return false
	}
}
