package checkdefinition

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const maxSSHListRules = 32

type SSHSpec struct {
	AllowedProtocolVersions []string `json:"allowed_protocol_versions,omitempty"`
	AllowedSoftware         []string `json:"allowed_software,omitempty"`
	DisallowedSoftware      []string `json:"disallowed_software,omitempty"`
	ForbiddenCommentTerms   []string `json:"forbidden_comment_terms,omitempty"`
	ForbidVersionDisclosure bool     `json:"forbid_version_disclosure,omitempty"`
	Remediation             string   `json:"remediation"`
}

type SSHInput struct {
	ProtocolVersion string
	Software        string
	SoftwareVersion string
	Comment         string
}

type SSHResult struct {
	Passed      bool
	Evidence    string
	Remediation string
}

func DecodeSSHSpec(check Check) (SSHSpec, error) {
	if err := Validate(check); err != nil {
		return SSHSpec{}, err
	}
	if check.Kind != "ssh" {
		return SSHSpec{}, errors.New("declarative check is not an SSH check")
	}
	var spec SSHSpec
	decoder := json.NewDecoder(bytes.NewReader(check.Spec))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return SSHSpec{}, fmt.Errorf("decode SSH check spec: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return SSHSpec{}, err
	}
	if err := validateSSHSpec(spec); err != nil {
		return SSHSpec{}, err
	}
	return spec, nil
}

func EvaluateSSH(check Check, input SSHInput) (SSHResult, error) {
	if err := requireObservational(check); err != nil {
		return SSHResult{}, err
	}
	spec, err := DecodeSSHSpec(check)
	if err != nil {
		return SSHResult{}, err
	}
	failures := sshFailures(spec, input)
	return SSHResult{Passed: len(failures) == 0, Evidence: strings.Join(failures, "; "), Remediation: spec.Remediation}, nil
}

func validateSSHSpec(spec SSHSpec) error {
	ruleCount := len(spec.AllowedProtocolVersions) + len(spec.AllowedSoftware) + len(spec.DisallowedSoftware) + len(spec.ForbiddenCommentTerms)
	if spec.ForbidVersionDisclosure {
		ruleCount++
	}
	if ruleCount == 0 {
		return errors.New("SSH check spec must declare at least one rule")
	}
	if ruleCount > maxSSHListRules {
		return fmt.Errorf("SSH check spec exceeds the %d-rule limit", maxSSHListRules)
	}
	if len(spec.AllowedSoftware) > 0 && len(spec.DisallowedSoftware) > 0 {
		return errors.New("SSH check cannot combine allowed and disallowed software lists")
	}
	if err := validateSSHValues(spec.AllowedProtocolVersions, "protocol version", 16); err != nil {
		return err
	}
	if err := validateSSHValues(spec.AllowedSoftware, "allowed software", 128); err != nil {
		return err
	}
	if err := validateSSHValues(spec.DisallowedSoftware, "disallowed software", 128); err != nil {
		return err
	}
	if err := validateSSHValues(spec.ForbiddenCommentTerms, "forbidden comment term", 128); err != nil {
		return err
	}
	if strings.TrimSpace(spec.Remediation) == "" {
		return errors.New("SSH check remediation is required")
	}
	return nil
}

func validateSSHValues(values []string, label string, limit int) error {
	seen := make(map[string]bool)
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" || len(normalized) > limit || seen[normalized] {
			return fmt.Errorf("SSH check contains an invalid or duplicate %s", label)
		}
		seen[normalized] = true
	}
	return nil
}

func sshFailures(spec SSHSpec, input SSHInput) []string {
	var failures []string
	if len(spec.AllowedProtocolVersions) > 0 && !containsFold(spec.AllowedProtocolVersions, input.ProtocolVersion) {
		failures = append(failures, fmt.Sprintf("SSH protocol version %q is not allowed", input.ProtocolVersion))
	}
	if len(spec.AllowedSoftware) > 0 && !containsFold(spec.AllowedSoftware, input.Software) {
		failures = append(failures, fmt.Sprintf("SSH software %q is not allowed", input.Software))
	}
	if containsFold(spec.DisallowedSoftware, input.Software) {
		failures = append(failures, fmt.Sprintf("SSH software %q is prohibited", input.Software))
	}
	comment := strings.ToLower(input.Comment)
	for _, term := range spec.ForbiddenCommentTerms {
		if strings.Contains(comment, strings.ToLower(term)) {
			failures = append(failures, fmt.Sprintf("SSH identification comment contains prohibited term %q", term))
		}
	}
	if spec.ForbidVersionDisclosure && strings.TrimSpace(input.SoftwareVersion) != "" {
		failures = append(failures, "SSH identification discloses a software version")
	}
	return failures
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}
