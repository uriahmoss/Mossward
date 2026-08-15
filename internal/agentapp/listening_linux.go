//go:build linux

package agentapp

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"mossward/internal/model"
)

const maximumListeningServices = 20000

type socketOwner struct {
	pid              int
	name, executable string
}

func platformListeningInventory() ([]model.ListeningService, error) {
	owners := linuxSocketOwners()
	services := []model.ListeningService{}
	for _, source := range []struct {
		path, protocol string
		ipv6, udp      bool
	}{
		{"/proc/net/tcp", "tcp", false, false}, {"/proc/net/tcp6", "tcp", true, false},
		{"/proc/net/udp", "udp", false, true}, {"/proc/net/udp6", "udp", true, true},
	} {
		items, err := readLinuxSockets(source.path, source.protocol, source.ipv6, source.udp, owners)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		services = append(services, items...)
		if len(services) >= maximumListeningServices {
			return services[:maximumListeningServices], nil
		}
	}
	return services, nil
}

func readLinuxSockets(path, protocol string, ipv6, udp bool, owners map[string]socketOwner) ([]model.ListeningService, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	services := []model.ListeningService{}
	scanner := bufio.NewScanner(file)
	if scanner.Scan() { /* skip header */
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || (!udp && fields[3] != "0A") || (udp && (fields[3] != "07" || !zeroProcRemote(fields[2]))) {
			continue
		}
		address, port, err := parseProcAddress(fields[1], ipv6)
		if err != nil {
			continue
		}
		owner := owners[fields[9]]
		services = append(services, model.ListeningService{Protocol: protocol, Address: address, Port: port, ProcessID: owner.pid, ProcessName: owner.name, Executable: owner.executable})
	}
	return services, scanner.Err()
}

func zeroProcRemote(value string) bool {
	address, port, found := strings.Cut(value, ":")
	return found && strings.Trim(address, "0") == "" && strings.Trim(port, "0") == ""
}

func parseProcAddress(value string, ipv6 bool) (string, int, error) {
	rawAddress, rawPort, found := strings.Cut(value, ":")
	if !found {
		return "", 0, fmt.Errorf("invalid socket address")
	}
	port, err := strconv.ParseUint(rawPort, 16, 16)
	if err != nil {
		return "", 0, err
	}
	bytes, err := hex.DecodeString(rawAddress)
	if err != nil || (!ipv6 && len(bytes) != 4) || (ipv6 && len(bytes) != 16) {
		return "", 0, fmt.Errorf("invalid socket address")
	}
	wordSize := 4
	for start := 0; start < len(bytes); start += wordSize {
		for left, right := start, start+wordSize-1; left < right; left, right = left+1, right-1 {
			bytes[left], bytes[right] = bytes[right], bytes[left]
		}
	}
	address, ok := netip.AddrFromSlice(bytes)
	if !ok {
		return "", 0, fmt.Errorf("invalid socket address")
	}
	return address.String(), int(port), nil
}

func linuxSocketOwners() map[string]socketOwner {
	owners := map[string]socketOwner{}
	processes, _ := filepath.Glob("/proc/[0-9]*")
	for _, process := range processes {
		pid, err := strconv.Atoi(filepath.Base(process))
		if err != nil {
			continue
		}
		nameBytes, _ := os.ReadFile(filepath.Join(process, "comm"))
		executable, _ := os.Readlink(filepath.Join(process, "exe"))
		fds, _ := filepath.Glob(filepath.Join(process, "fd", "*"))
		for _, fd := range fds {
			target, err := os.Readlink(fd)
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if _, exists := owners[inode]; !exists {
				owners[inode] = socketOwner{pid: pid, name: strings.TrimSpace(string(nameBytes)), executable: executable}
			}
		}
	}
	return owners
}
