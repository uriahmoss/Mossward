package agentupdate

import (
	"strconv"
	"strings"
)

func IsUpgrade(current, target string) bool {
	currentParts, currentPrerelease, ok := parseVersion(current)
	if !ok {
		return false
	}
	targetParts, targetPrerelease, ok := parseVersion(target)
	if !ok {
		return false
	}
	for index := range currentParts {
		if targetParts[index] != currentParts[index] {
			return targetParts[index] > currentParts[index]
		}
	}
	if currentPrerelease == targetPrerelease {
		return false
	}
	if currentPrerelease == "" {
		return false
	}
	if targetPrerelease == "" {
		return true
	}
	return targetPrerelease > currentPrerelease
}

func parseVersion(value string) ([3]int, string, bool) {
	var parsed [3]int
	if !versionPattern.MatchString(value) {
		return parsed, "", false
	}
	core, prerelease, _ := strings.Cut(value, "-")
	parts := strings.Split(core, ".")
	for index, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil {
			return parsed, "", false
		}
		parsed[index] = number
	}
	return parsed, prerelease, true
}
