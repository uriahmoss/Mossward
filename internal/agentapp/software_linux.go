//go:build linux

package agentapp

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	"mossward/internal/model"
)

const maximumInstalledSoftware = 10000

func platformSoftwareInventory() ([]model.InstalledSoftware, error) {
	if _, err := os.Stat("/var/lib/dpkg/status"); err == nil {
		return readPackageParagraphs("/var/lib/dpkg/status", "Package", "Version", "Architecture", "Status", "install ok installed", "dpkg")
	}
	if _, err := os.Stat("/lib/apk/db/installed"); err == nil {
		return readPackageParagraphs("/lib/apk/db/installed", "P", "V", "A", "", "", "apk")
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		return readRPMInventory()
	}
	return nil, errors.New("supported Linux package database not found")
}

func readPackageParagraphs(path, nameKey, versionKey, architectureKey, stateKey, requiredState, source string) ([]model.InstalledSoftware, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	items, fields := []model.InstalledSoftware{}, map[string]string{}
	flush := func() {
		if fields[nameKey] != "" && (stateKey == "" || fields[stateKey] == requiredState) && len(items) < maximumInstalledSoftware {
			items = append(items, model.InstalledSoftware{Name: fields[nameKey], Version: fields[versionKey], Architecture: fields[architectureKey], Source: source})
		}
		fields = map[string]string{}
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if found {
			fields[key] = strings.TrimSpace(value)
		}
	}
	flush()
	return items, scanner.Err()
}

func readRPMInventory() ([]model.InstalledSoftware, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "rpm", "-qa", "--qf", `%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n`).Output()
	if err != nil {
		return nil, err
	}
	items := []model.InstalledSoftware{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || fields[0] == "" {
			continue
		}
		items = append(items, model.InstalledSoftware{Name: fields[0], Version: fields[1], Architecture: fields[2], Source: "rpm"})
		if len(items) == maximumInstalledSoftware {
			break
		}
	}
	return items, nil
}
