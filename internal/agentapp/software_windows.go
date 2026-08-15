//go:build windows

package agentapp

import (
	"strings"

	"golang.org/x/sys/windows/registry"
	"mossward/internal/model"
)

const maximumInstalledSoftware = 10000

func platformSoftwareInventory() ([]model.InstalledSoftware, error) {
	items, seen := []model.InstalledSoftware{}, map[string]bool{}
	const uninstallPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		root, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallPath, registry.ENUMERATE_SUB_KEYS|view)
		if err != nil {
			continue
		}
		names, _ := root.ReadSubKeyNames(-1)
		root.Close()
		for _, subkey := range names {
			key, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallPath+`\`+subkey, registry.QUERY_VALUE|view)
			if err != nil {
				continue
			}
			name, _, _ := key.GetStringValue("DisplayName")
			version, _, _ := key.GetStringValue("DisplayVersion")
			publisher, _, _ := key.GetStringValue("Publisher")
			key.Close()
			name, version, publisher = strings.TrimSpace(name), strings.TrimSpace(version), strings.TrimSpace(publisher)
			identity := strings.ToLower(name + "\x00" + version)
			if name == "" || seen[identity] {
				continue
			}
			seen[identity] = true
			items = append(items, model.InstalledSoftware{Name: name, Version: version, Publisher: publisher, Source: "windows_registry"})
			if len(items) == maximumInstalledSoftware {
				return items, nil
			}
		}
	}
	return items, nil
}
