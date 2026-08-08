package checkdefinition

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvaluateSSHReportsIdentificationFailures(t *testing.T) {
	check := sshCheck(`{"allowed_protocol_versions":["2.0"],"allowed_software":["OpenSSH"],"forbidden_comment_terms":["legacy"],"forbid_version_disclosure":true,"remediation":"Harden SSH."}`)
	result, err := EvaluateSSH(check, SSHInput{ProtocolVersion: "1.99", Software: "Dropbear", SoftwareVersion: "2024.86", Comment: "legacy appliance"})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"1.99", "Dropbear", "legacy", "software version"} {
		if !strings.Contains(result.Evidence, expected) {
			t.Fatalf("evidence %q does not contain %q", result.Evidence, expected)
		}
	}
	if result.Passed {
		t.Fatal("noncompliant SSH identification passed")
	}
}

func TestEvaluateSSHPassesCompliantIdentification(t *testing.T) {
	check := sshCheck(`{"allowed_protocol_versions":["2.0"],"allowed_software":["OpenSSH"],"remediation":"Harden SSH."}`)
	result, err := EvaluateSSH(check, SSHInput{ProtocolVersion: "2.0", Software: "openssh"})
	if err != nil || !result.Passed {
		t.Fatalf("unexpected SSH result: %#v, %v", result, err)
	}
}

func TestDecodeSSHSpecRejectsInvalidRules(t *testing.T) {
	tests := []string{
		`{"allowed_software":["OpenSSH"],"disallowed_software":["Dropbear"],"remediation":"Fix it."}`,
		`{"allowed_protocol_versions":["2.0","2.0"],"remediation":"Fix it."}`,
		`{"forbidden_comment_terms":[""],"remediation":"Fix it."}`,
		`{"unknown":true,"remediation":"Fix it."}`,
		`{"remediation":"Fix it."}`,
	}
	for _, spec := range tests {
		if _, err := DecodeSSHSpec(sshCheck(spec)); err == nil {
			t.Fatalf("invalid SSH spec was accepted: %s", spec)
		}
	}
}

func sshCheck(spec string) Check {
	return Check{SchemaVersion: SchemaVersion, ID: "mossward.ssh.test", Version: "1.0.0", Kind: "ssh",
		Title: "SSH test", Severity: "medium", Spec: json.RawMessage(spec)}
}
