//go:build windows

package agentapp

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
	"mossward/internal/model"
)

func platformOSInventory() (model.EndpointOSInventory, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return model.EndpointOSInventory{}, err
	}
	defer key.Close()
	name, _, _ := key.GetStringValue("ProductName")
	version, _, _ := key.GetStringValue("DisplayVersion")
	if version == "" {
		version, _, _ = key.GetStringValue("ReleaseId")
	}
	if version == "" {
		version, _, _ = key.GetStringValue("CurrentVersion")
	}
	build, _, _ := key.GetStringValue("CurrentBuildNumber")
	ubr, _, _ := key.GetIntegerValue("UBR")
	fullBuild := fmt.Sprintf("%s.%d", build, ubr)
	return model.EndpointOSInventory{Family: "windows", Name: strings.TrimSpace(name), Version: strings.TrimSpace(version), Build: fullBuild,
		Kernel: fullBuild, Patches: []model.EndpointPatch{{ID: "build:" + fullBuild, Description: "Windows cumulative update build revision"}}}, nil
}
