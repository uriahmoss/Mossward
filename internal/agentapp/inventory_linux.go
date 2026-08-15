//go:build linux

package agentapp

import (
	"bufio"
	"os"
	"strings"
	"syscall"

	"mossward/internal/model"
)

func platformOSInventory() (model.EndpointOSInventory, error) {
	values := map[string]string{}
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return model.EndpointOSInventory{}, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if found {
			values[key] = strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	if err := scanner.Err(); err != nil {
		return model.EndpointOSInventory{}, err
	}
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return model.EndpointOSInventory{}, err
	}
	kernel := charsToString(uts.Release[:])
	name, version := values["NAME"], values["VERSION_ID"]
	if name == "" {
		name = values["ID"]
	}
	if version == "" {
		version = values["VERSION"]
	}
	return model.EndpointOSInventory{Family: "linux", Name: name, Version: version, Build: values["BUILD_ID"], Kernel: kernel,
		Patches: []model.EndpointPatch{{ID: "kernel:" + kernel, Description: "Running Linux kernel security patch level"}}}, nil
}

func charsToString(values []int8) string {
	bytes := make([]byte, 0, len(values))
	for _, value := range values {
		if value == 0 {
			break
		}
		bytes = append(bytes, byte(value))
	}
	return string(bytes)
}
