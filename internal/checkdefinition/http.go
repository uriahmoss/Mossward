package checkdefinition

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

const (
	maxHTTPRules       = 32
	maxHeaderValueSize = 512
)

type HTTPSpec struct {
	RequireHTTPS       bool                `json:"require_https,omitempty"`
	RequiredHeaders    []string            `json:"required_headers,omitempty"`
	ForbiddenHeaders   []string            `json:"forbidden_headers,omitempty"`
	HeaderContains     map[string][]string `json:"header_contains,omitempty"`
	AllowedStatusCodes []int               `json:"allowed_status_codes,omitempty"`
	Remediation        string              `json:"remediation"`
}

type HTTPInput struct {
	Secure     bool
	StatusCode int
	Headers    http.Header
}

type HTTPResult struct {
	Passed      bool
	Evidence    string
	Remediation string
}

func DecodeHTTPSpec(check Check) (HTTPSpec, error) {
	if err := Validate(check); err != nil {
		return HTTPSpec{}, err
	}
	if check.Kind != "http" {
		return HTTPSpec{}, errors.New("declarative check is not an HTTP check")
	}
	var spec HTTPSpec
	decoder := json.NewDecoder(bytes.NewReader(check.Spec))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return HTTPSpec{}, fmt.Errorf("decode HTTP check spec: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return HTTPSpec{}, err
	}
	if err := validateHTTPSpec(spec); err != nil {
		return HTTPSpec{}, err
	}
	return spec, nil
}

func EvaluateHTTP(check Check, input HTTPInput) (HTTPResult, error) {
	spec, err := DecodeHTTPSpec(check)
	if err != nil {
		return HTTPResult{}, err
	}
	failures := httpFailures(spec, input)
	return HTTPResult{Passed: len(failures) == 0, Evidence: strings.Join(failures, "; "), Remediation: spec.Remediation}, nil
}

func validateHTTPSpec(spec HTTPSpec) error {
	ruleCount := len(spec.RequiredHeaders) + len(spec.ForbiddenHeaders) + len(spec.AllowedStatusCodes)
	if spec.RequireHTTPS {
		ruleCount++
	}
	if ruleCount == 0 {
		return errors.New("HTTP check spec must declare at least one rule")
	}
	if ruleCount > maxHTTPRules {
		return fmt.Errorf("HTTP check spec exceeds the %d-rule limit", maxHTTPRules)
	}
	if strings.TrimSpace(spec.Remediation) == "" {
		return errors.New("HTTP check remediation is required")
	}
	seen := make(map[string]bool)
	for _, name := range append(append([]string{}, spec.RequiredHeaders...), spec.ForbiddenHeaders...) {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if !validHeaderName(canonical) || seen[strings.ToLower(canonical)] {
			return errors.New("HTTP check contains an invalid or duplicate header rule")
		}
		seen[strings.ToLower(canonical)] = true
	}
	valueHeaders := make(map[string]bool)
	for name, values := range spec.HeaderContains {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		normalized := strings.ToLower(canonical)
		if !validHeaderName(canonical) || len(values) == 0 || valueHeaders[normalized] {
			return errors.New("HTTP check contains an invalid header-value rule")
		}
		valueHeaders[normalized] = true
		ruleCount += len(values)
		for _, value := range values {
			if strings.TrimSpace(value) == "" || len(value) > maxHeaderValueSize {
				return errors.New("HTTP check header value is empty or too large")
			}
		}
	}
	if ruleCount > maxHTTPRules {
		return fmt.Errorf("HTTP check spec exceeds the %d-rule limit", maxHTTPRules)
	}
	statusSeen := make(map[int]bool)
	for _, status := range spec.AllowedStatusCodes {
		if status < 100 || status > 599 || statusSeen[status] {
			return errors.New("HTTP check contains an invalid or duplicate status code")
		}
		statusSeen[status] = true
	}
	return nil
}

func httpFailures(spec HTTPSpec, input HTTPInput) []string {
	var failures []string
	if spec.RequireHTTPS && !input.Secure {
		failures = append(failures, "the service responded over cleartext HTTP")
	}
	for _, name := range spec.RequiredHeaders {
		if strings.TrimSpace(input.Headers.Get(name)) == "" {
			failures = append(failures, fmt.Sprintf("required header %s is missing", http.CanonicalHeaderKey(name)))
		}
	}
	for _, name := range spec.ForbiddenHeaders {
		if strings.TrimSpace(input.Headers.Get(name)) != "" {
			failures = append(failures, fmt.Sprintf("forbidden header %s is present", http.CanonicalHeaderKey(name)))
		}
	}
	for name, values := range spec.HeaderContains {
		actual := strings.ToLower(input.Headers.Get(name))
		for _, expected := range values {
			if !strings.Contains(actual, strings.ToLower(expected)) {
				failures = append(failures, fmt.Sprintf("header %s does not contain the required value", http.CanonicalHeaderKey(name)))
			}
		}
	}
	if len(spec.AllowedStatusCodes) > 0 && !containsStatus(spec.AllowedStatusCodes, input.StatusCode) {
		failures = append(failures, fmt.Sprintf("HTTP status %d is not allowed", input.StatusCode))
	}
	sort.Strings(failures)
	return failures
}

func validHeaderName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, character := range name {
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", character) &&
			(character < '0' || character > '9') && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') {
			return false
		}
	}
	return true
}

func containsStatus(statuses []int, target int) bool {
	for _, status := range statuses {
		if status == target {
			return true
		}
	}
	return false
}
