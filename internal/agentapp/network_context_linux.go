//go:build linux

package agentapp

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
)

func platformNetworkNameContext() map[string]networkNameContext {
	contexts := map[string]networkNameContext{}
	file, err := os.Open("/etc/hosts")
	if err != nil {
		return contexts
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		address, err := netip.ParseAddr(fields[0])
		if err != nil || address.IsLoopback() || strings.TrimSpace(fields[1]) == "" {
			continue
		}
		contexts[address.String()] = networkNameContext{hostname: strings.ToLower(fields[1]), source: "hosts_file"}
	}
	return contexts
}
