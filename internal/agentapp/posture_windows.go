//go:build windows

package agentapp

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
	"mossward/internal/model"
)

func platformPostureEvidence() ([]model.PostureEvidence, error) {
	return []model.PostureEvidence{windowsSecureBoot(), windowsFirewall(), windowsDiskEncryption()}, nil
}

func windowsSecureBoot() model.PostureEvidence {
	evidence := model.PostureEvidence{ID: "secure_boot", Title: "Secure Boot", Status: "unknown", Detail: "Secure Boot state is unavailable"}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, registry.QUERY_VALUE)
	if err != nil {
		return evidence
	}
	defer key.Close()
	value, _, err := key.GetIntegerValue("UEFISecureBootEnabled")
	if err != nil {
		return evidence
	}
	evidence.Status, evidence.Detail = "fail", "Secure Boot is disabled"
	if value == 1 {
		evidence.Status, evidence.Detail = "pass", "Secure Boot is enabled"
	}
	return evidence
}

func windowsFirewall() model.PostureEvidence {
	evidence := model.PostureEvidence{ID: "host_firewall", Title: "Windows Firewall", Status: "unknown", Detail: "Firewall profile state is unavailable"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "netsh.exe", "advfirewall", "show", "allprofiles", "state").Output()
	if err != nil {
		return evidence
	}
	upper := strings.ToUpper(string(output))
	enabled := strings.Count(upper, "STATE") == strings.Count(upper, "ON") && strings.Count(upper, "STATE") >= 3
	evidence.Status, evidence.Detail = "fail", "One or more Windows Firewall profiles are disabled"
	if enabled {
		evidence.Status, evidence.Detail = "pass", "All Windows Firewall profiles are enabled"
	}
	return evidence
}

func windowsDiskEncryption() model.PostureEvidence {
	evidence := model.PostureEvidence{ID: "system_volume_encryption", Title: "System volume encryption", Status: "unknown", Detail: "BitLocker state is unavailable"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "manage-bde.exe", "-status", "C:").Output()
	if err != nil {
		return evidence
	}
	upper := strings.ToUpper(string(output))
	evidence.Status, evidence.Detail = "fail", "System volume is not fully encrypted"
	if strings.Contains(upper, "PERCENTAGE ENCRYPTED:") && strings.Contains(upper, "100%") {
		evidence.Status, evidence.Detail = "pass", "System volume is fully encrypted"
	}
	return evidence
}
