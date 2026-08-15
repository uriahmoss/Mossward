//go:build windows

package agentapp

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

func platformNetworkNameContext() map[string]networkNameContext {
	contexts := map[string]networkNameContext{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ipconfig.exe", "/displaydns").Output()
	if err != nil {
		return contexts
	}
	currentName := ""
	for _, raw := range strings.Split(string(output), "\n") {
		label, value, found := strings.Cut(strings.TrimSpace(raw), ":")
		if !found {
			continue
		}
		label, value = strings.ToLower(strings.TrimSpace(label)), strings.TrimSpace(value)
		if strings.Contains(label, "record name") {
			currentName = strings.ToLower(value)
			continue
		}
		if currentName == "" || (!strings.Contains(label, "host) record") && !strings.Contains(label, "aaaa record")) {
			continue
		}
		address, err := netip.ParseAddr(value)
		if err == nil && !address.IsLoopback() {
			contexts[address.String()] = networkNameContext{hostname: currentName, source: "windows_dns_cache"}
		}
	}
	return contexts
}
