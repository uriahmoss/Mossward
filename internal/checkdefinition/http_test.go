package checkdefinition

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestEvaluateHTTPReportsFailedRules(t *testing.T) {
	check := httpCheck(`{
		"require_https":true,
		"required_headers":["Content-Security-Policy"],
		"forbidden_headers":["Server"],
		"header_contains":{"X-Content-Type-Options":["nosniff"]},
		"allowed_status_codes":[200],
		"remediation":"Harden the HTTP response."
	}`)
	result, err := EvaluateHTTP(check, HTTPInput{StatusCode: 302, Headers: http.Header{"Server": []string{"nginx"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"cleartext", "Content-Security-Policy", "Server", "X-Content-Type-Options", "302"} {
		if !strings.Contains(result.Evidence, expected) {
			t.Fatalf("evidence %q does not contain %q", result.Evidence, expected)
		}
	}
	if result.Passed || result.Remediation == "" {
		t.Fatalf("unexpected HTTP result: %#v", result)
	}
}

func TestEvaluateHTTPPassesCompliantResponse(t *testing.T) {
	check := httpCheck(`{"require_https":true,"required_headers":["Content-Security-Policy"],"header_contains":{"X-Content-Type-Options":["nosniff"]},"allowed_status_codes":[200],"remediation":"Harden the HTTP response."}`)
	result, err := EvaluateHTTP(check, HTTPInput{Secure: true, StatusCode: 200, Headers: http.Header{
		"Content-Security-Policy": []string{"default-src 'self'"}, "X-Content-Type-Options": []string{"nosniff"},
	}})
	if err != nil || !result.Passed || result.Evidence != "" {
		t.Fatalf("unexpected HTTP result: %#v, %v", result, err)
	}
}

func TestObservationalEvaluatorRejectsIntrusiveCheck(t *testing.T) {
	check := httpCheck(`{"require_https":true,"remediation":"Use HTTPS."}`)
	check.ExecutionClass = ExecutionIntrusive
	if _, err := EvaluateHTTP(check, HTTPInput{}); err == nil {
		t.Fatal("HTTP evaluator accepted an intrusive check")
	}
}

func TestDecodeHTTPSpecRejectsUnknownUnsafeAndExcessiveRules(t *testing.T) {
	tests := []string{
		`{"unknown":true,"remediation":"Fix it."}`,
		`{"required_headers":["Bad Header"],"remediation":"Fix it."}`,
		`{"allowed_status_codes":[99],"remediation":"Fix it."}`,
		`{"required_headers":["X-Test","x-test"],"remediation":"Fix it."}`,
		`{"remediation":"Fix it."}`,
	}
	for _, spec := range tests {
		if _, err := DecodeHTTPSpec(httpCheck(spec)); err == nil {
			t.Fatalf("invalid HTTP spec was accepted: %s", spec)
		}
	}
	statuses := make([]int, maxHTTPRules+1)
	for index := range statuses {
		statuses[index] = 200 + index
	}
	spec, err := json.Marshal(HTTPSpec{AllowedStatusCodes: statuses, Remediation: "Fix it."})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeHTTPSpec(httpCheck(string(spec))); err == nil {
		t.Fatal("excessive HTTP rules were accepted")
	}
}

func httpCheck(spec string) Check {
	return Check{SchemaVersion: SchemaVersion, ID: "mossward.http.test", Version: "1.0.0", Kind: "http",
		Title: "HTTP test", Severity: "medium", Spec: json.RawMessage(spec)}
}
