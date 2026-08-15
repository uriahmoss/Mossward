//go:build linux

package agentapp

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"mossward/internal/model"
)

const maximumNetworkConnections = 10000

func platformNetworkInventory() ([]model.NetworkConnection, error) {
	owners := linuxSocketOwners()
	listeners := linuxListeningPorts()
	connections := []model.NetworkConnection{}
	for _, source := range []struct {
		path, protocol string
		ipv6, udp      bool
	}{
		{"/proc/net/tcp", "tcp", false, false}, {"/proc/net/tcp6", "tcp", true, false},
		{"/proc/net/udp", "udp", false, true}, {"/proc/net/udp6", "udp", true, true},
	} {
		items, err := readLinuxConnections(source.path, source.protocol, source.ipv6, source.udp, owners, listeners)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		connections = append(connections, items...)
		if len(connections) >= maximumNetworkConnections {
			return connections[:maximumNetworkConnections], nil
		}
	}
	return connections, nil
}

func readLinuxConnections(path, protocol string, ipv6, udp bool, owners map[string]socketOwner, listeners map[string]bool) ([]model.NetworkConnection, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	connections := []model.NetworkConnection{}
	scanner := bufio.NewScanner(file)
	if scanner.Scan() { /* header */
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || (!udp && fields[3] != "01") || (udp && zeroProcRemote(fields[2])) {
			continue
		}
		localAddress, localPort, localErr := parseProcAddress(fields[1], ipv6)
		remoteAddress, remotePort, remoteErr := parseProcAddress(fields[2], ipv6)
		if localErr != nil || remoteErr != nil || remotePort == 0 || listeners[protocol+":"+strconv.Itoa(localPort)] {
			continue
		}
		owner := owners[fields[9]]
		connections = append(connections, model.NetworkConnection{Protocol: protocol, LocalAddress: localAddress, LocalPort: localPort,
			RemoteAddress: remoteAddress, RemotePort: remotePort, ProcessID: owner.pid, ProcessName: owner.name, Direction: "outbound_candidate"})
	}
	return connections, scanner.Err()
}

func linuxListeningPorts() map[string]bool {
	ports := map[string]bool{}
	for _, source := range []struct{ path, protocol, state string }{{"/proc/net/tcp", "tcp", "0A"}, {"/proc/net/tcp6", "tcp", "0A"}, {"/proc/net/udp", "udp", "07"}, {"/proc/net/udp6", "udp", "07"}} {
		file, err := os.Open(source.path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		if scanner.Scan() { /* header */
		}
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 || fields[3] != source.state {
				continue
			}
			_, portText, found := strings.Cut(fields[1], ":")
			port, err := strconv.ParseUint(portText, 16, 16)
			if found && err == nil {
				ports[source.protocol+":"+strconv.Itoa(int(port))] = true
			}
		}
		file.Close()
	}
	return ports
}
