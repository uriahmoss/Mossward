//go:build linux

package agentapp

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"mossward/internal/model"
)

func platformPostureEvidence() ([]model.PostureEvidence, error) {
	return []model.PostureEvidence{linuxSecureBoot(), linuxRootEncryption(), linuxFirewall()}, nil
}

func linuxSecureBoot() model.PostureEvidence {
	evidence := model.PostureEvidence{ID: "secure_boot", Title: "Secure Boot", Status: "unknown", Detail: "Secure Boot state is unavailable"}
	paths, _ := filepath.Glob("/sys/firmware/efi/efivars/SecureBoot-*")
	if len(paths) == 0 {
		return evidence
	}
	data, err := os.ReadFile(paths[0])
	if err != nil || len(data) < 5 {
		return evidence
	}
	evidence.Status, evidence.Detail = "fail", "Secure Boot is disabled"
	if data[len(data)-1] == 1 {
		evidence.Status, evidence.Detail = "pass", "Secure Boot is enabled"
	}
	return evidence
}

func linuxRootEncryption() model.PostureEvidence {
	evidence := model.PostureEvidence{ID: "root_volume_encryption", Title: "Root volume encryption", Status: "unknown", Detail: "Root volume source is unavailable"}
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return evidence
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "/" {
			continue
		}
		evidence.Status, evidence.Detail = "fail", "Root filesystem is not backed by a confirmed encrypted device-mapper target"
		if uuid := linuxDeviceMapperUUID(fields[0]); strings.HasPrefix(strings.ToUpper(uuid), "CRYPT-") {
			evidence.Status, evidence.Detail = "pass", "Root filesystem is backed by a dm-crypt target"
		} else if strings.HasPrefix(fields[0], "/dev/mapper/") || strings.HasPrefix(fields[0], "/dev/dm-") {
			evidence.Status, evidence.Detail = "unknown", "Root filesystem uses device mapper but dm-crypt could not be confirmed"
		}
		return evidence
	}
	return evidence
}

func linuxDeviceMapperUUID(device string) string {
	resolved, err := filepath.EvalSymlinks(device)
	if err != nil {
		resolved = device
	}
	data, err := os.ReadFile(filepath.Join("/sys/class/block", filepath.Base(resolved), "dm", "uuid"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func linuxFirewall() model.PostureEvidence {
	evidence := model.PostureEvidence{ID: "host_firewall", Title: "Host firewall", Status: "unknown", Detail: "nftables state is unavailable"}
	if _, err := exec.LookPath("nft"); err != nil {
		return evidence
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "nft", "list", "ruleset").Output()
	if err != nil {
		return evidence
	}
	evidence.Status, evidence.Detail = "fail", "nftables has no active rules"
	if strings.TrimSpace(string(output)) != "" {
		evidence.Status, evidence.Detail = "pass", "nftables has an active ruleset"
	}
	return evidence
}
