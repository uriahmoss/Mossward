//go:build windows

package agentapp

import (
	"context"
	"encoding/csv"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"mossward/internal/model"
)

const maximumListeningServices = 20000

func platformListeningInventory() ([]model.ListeningService, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "netstat.exe", "-ano", "-p", "tcp").Output()
	if err != nil {
		return nil, err
	}
	udpOutput, err := exec.CommandContext(ctx, "netstat.exe", "-ano", "-p", "udp").Output()
	if err != nil {
		return nil, err
	}
	owners := windowsProcessNames(ctx)
	services := parseWindowsNetstat(string(output), owners, false)
	services = append(services, parseWindowsNetstat(string(udpOutput), owners, true)...)
	if len(services) > maximumListeningServices {
		services = services[:maximumListeningServices]
	}
	return services, nil
}

func parseWindowsNetstat(output string, owners map[int]string, udp bool) []model.ListeningService {
	services := []model.ListeningService{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if (!udp && (len(fields) != 5 || fields[0] != "TCP" || fields[3] != "LISTENING")) || (udp && (len(fields) != 4 || fields[0] != "UDP")) {
			continue
		}
		pidField := fields[len(fields)-1]
		pid, err := strconv.Atoi(pidField)
		if err != nil {
			continue
		}
		address, port, ok := splitWindowsAddress(fields[1])
		if !ok {
			continue
		}
		protocol := "tcp"
		if udp {
			protocol = "udp"
		}
		services = append(services, model.ListeningService{Protocol: protocol, Address: address, Port: port, ProcessID: pid, ProcessName: owners[pid]})
	}
	return services
}

func splitWindowsAddress(value string) (string, int, bool) {
	host, portValue, err := net.SplitHostPort(value)
	if err != nil {
		index := strings.LastIndex(value, ":")
		if index < 0 {
			return "", 0, false
		}
		host, portValue = value[:index], value[index+1:]
	}
	port, err := strconv.Atoi(portValue)
	return strings.Trim(host, "[]"), port, err == nil && port > 0 && port <= 65535
}

func windowsProcessNames(ctx context.Context) map[int]string {
	owners := map[int]string{}
	output, err := exec.CommandContext(ctx, "tasklist.exe", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return owners
	}
	rows, err := csv.NewReader(strings.NewReader(string(output))).ReadAll()
	if err != nil {
		return owners
	}
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		pid, err := strconv.Atoi(row[1])
		if err == nil {
			owners[pid] = row[0]
		}
	}
	return owners
}
