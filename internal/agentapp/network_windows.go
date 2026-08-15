//go:build windows

package agentapp

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"mossward/internal/model"
)

const maximumNetworkConnections = 10000

func platformNetworkInventory() ([]model.NetworkConnection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "netstat.exe", "-ano", "-p", "tcp").Output()
	if err != nil {
		return nil, err
	}
	owners := windowsProcessNames(ctx)
	listeners := map[int]bool{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] != "TCP" || fields[3] != "LISTENING" {
			continue
		}
		_, port, ok := splitWindowsAddress(fields[1])
		if ok {
			listeners[port] = true
		}
	}
	connections := []model.NetworkConnection{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] != "TCP" || fields[3] != "ESTABLISHED" {
			continue
		}
		localAddress, localPort, localOK := splitWindowsAddress(fields[1])
		remoteAddress, remotePort, remoteOK := splitWindowsAddress(fields[2])
		pid, pidErr := strconv.Atoi(fields[4])
		if !localOK || !remoteOK || pidErr != nil || listeners[localPort] {
			continue
		}
		connections = append(connections, model.NetworkConnection{Protocol: "tcp", LocalAddress: localAddress, LocalPort: localPort,
			RemoteAddress: remoteAddress, RemotePort: remotePort, ProcessID: pid, ProcessName: owners[pid], Direction: "outbound_candidate"})
		if len(connections) == maximumNetworkConnections {
			break
		}
	}
	return connections, nil
}
