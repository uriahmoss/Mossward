package agentmodule

import (
	"encoding/json"
	"errors"
	"fmt"
)

type DeclarativePackage struct {
	SchemaVersion int                `json:"schema_version"`
	Checks        []DeclarativeCheck `json:"checks"`
}

type DeclarativeCheck struct {
	ID       string     `json:"id"`
	Source   Permission `json:"source"`
	Field    string     `json:"field"`
	Operator string     `json:"operator"`
	Value    string     `json:"value"`
	Severity string     `json:"severity"`
}

func ValidateDeclarativePackage(pkg []byte, manifest Manifest) error {
	if manifest.Kind != KindDeclarative {
		return errors.New("module is not declarative")
	}
	var definition DeclarativePackage
	if err := json.Unmarshal(pkg, &definition); err != nil || definition.SchemaVersion != 1 || len(definition.Checks) == 0 || len(definition.Checks) > 1000 {
		return errors.New("declarative module package is invalid")
	}
	seen := map[string]bool{}
	for _, check := range definition.Checks {
		if !moduleIDPattern.MatchString(check.ID) || seen[check.ID] {
			return errors.New("declarative check identifier is invalid or duplicated")
		}
		seen[check.ID] = true
		if !permissionDeclared(manifest, check.Source) {
			return fmt.Errorf("declarative check %q uses an undeclared permission", check.ID)
		}
		if check.Field == "" || (check.Operator != "equals" && check.Operator != "not_equals" && check.Operator != "contains" && check.Operator != "exists") {
			return fmt.Errorf("declarative check %q is invalid", check.ID)
		}
		if check.Severity != "info" && check.Severity != "low" && check.Severity != "medium" && check.Severity != "high" && check.Severity != "critical" {
			return fmt.Errorf("declarative check %q severity is invalid", check.ID)
		}
	}
	return nil
}

func permissionDeclared(manifest Manifest, permission Permission) bool {
	for _, declared := range manifest.Permissions {
		if declared == permission {
			return true
		}
	}
	return false
}
