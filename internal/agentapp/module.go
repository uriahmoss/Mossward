package agentapp

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"mossward/internal/agentmodule"
)

const maximumModuleCrashes = 3

var moduleOperatingSystem, moduleArchitecture = runtime.GOOS, runtime.GOARCH

type moduleState struct {
	SchemaVersion int                        `json:"schema_version"`
	Modules       map[string]installedModule `json:"modules"`
}

type installedModule struct {
	ReleaseID         string                `json:"release_id"`
	Manifest          agentmodule.Manifest  `json:"manifest"`
	Healthy           bool                  `json:"healthy"`
	CrashCount        int                   `json:"crash_count"`
	Error             string                `json:"error,omitempty"`
	InstalledAt       time.Time             `json:"installed_at"`
	PreviousPath      string                `json:"previous_path,omitempty"`
	PreviousReleaseID string                `json:"previous_release_id,omitempty"`
	PreviousManifest  *agentmodule.Manifest `json:"previous_manifest,omitempty"`
}

func moduleHealth(directory string) []agentmodule.Health {
	state, err := loadModuleState(directory)
	if err != nil {
		return nil
	}
	reports := make([]agentmodule.Health, 0, len(state.Modules))
	for _, module := range state.Modules {
		reports = append(reports, agentmodule.Health{ModuleID: module.Manifest.ID, Version: module.Manifest.Version,
			Healthy: module.Healthy, CrashCount: module.CrashCount, Error: module.Error, ObservedAt: module.InstalledAt})
	}
	return reports
}

func applyModuleOffers(directory string, offers []agentmodule.Offer, trust map[string]ed25519.PublicKey) error {
	if len(offers) == 1 && offers[0].Disabled {
		return disableAllModules(directory)
	}
	for _, offer := range offers {
		if err := installModuleOffer(directory, offer, trust); err != nil {
			return err
		}
	}
	return nil
}

func installModuleOffer(directory string, offer agentmodule.Offer, trust map[string]ed25519.PublicKey) error {
	keyID, err := moduleEnvelopePublisher(offer.Envelope)
	if err != nil {
		return err
	}
	key := trust[keyID]
	manifest, pkg, err := agentmodule.Verify(bytes.NewReader(offer.Envelope), key, keyID)
	if err != nil {
		return err
	}
	if !manifest.Compatible(Version, moduleOperatingSystem, moduleArchitecture) {
		return errors.New("endpoint module is incompatible with this agent")
	}
	if manifest.Kind == agentmodule.KindDeclarative {
		if err := agentmodule.ValidateDeclarativePackage(pkg, manifest); err != nil {
			return err
		}
	}
	state, err := loadModuleState(directory)
	if err != nil {
		return err
	}
	current, exists := state.Modules[manifest.ID]
	if exists && current.ReleaseID == offer.ReleaseID {
		return nil
	}
	versionDirectory := filepath.Join(directory, "packages", manifest.ID, manifest.Version)
	if err := os.MkdirAll(versionDirectory, 0o750); err != nil {
		return err
	}
	packagePath := filepath.Join(versionDirectory, "package.bin")
	if err := writeModuleFile(packagePath, pkg, 0o600); err != nil {
		return err
	}
	if manifest.Kind == agentmodule.KindNative {
		if err := installNativeEntrypoint(versionDirectory, pkg, manifest.Entrypoint); err != nil {
			return err
		}
	}
	envelopePath := filepath.Join(versionDirectory, "envelope.json")
	if err := writeModuleFile(envelopePath, offer.Envelope, 0o600); err != nil {
		return err
	}
	previous := ""
	if exists {
		previous = filepath.Join(directory, "packages", current.Manifest.ID, current.Manifest.Version)
	}
	installed := installedModule{ReleaseID: offer.ReleaseID, Manifest: manifest, Healthy: true, InstalledAt: time.Now().UTC(), PreviousPath: previous}
	if exists {
		installed.PreviousReleaseID, installed.PreviousManifest = current.ReleaseID, &current.Manifest
	}
	state.Modules[manifest.ID] = installed
	if err := saveModuleState(directory, state); err != nil {
		return err
	}
	slog.Info("Endpoint module installed", "module_id", manifest.ID, "version", manifest.Version, "kind", manifest.Kind)
	return nil
}

func installNativeEntrypoint(directory string, pkg []byte, entrypoint string) error {
	archive, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil || len(archive.File) != 1 || archive.File[0].Name != entrypoint || archive.File[0].FileInfo().IsDir() {
		return errors.New("native module package must contain only its declared entrypoint")
	}
	reader, err := archive.File[0].Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, agentmodule.MaximumPackageBytes+1))
	if err != nil || len(data) > agentmodule.MaximumPackageBytes {
		return errors.New("native module entrypoint is too large")
	}
	return writeModuleFile(filepath.Join(directory, entrypoint), data, 0o700)
}

func recordModuleFailure(directory, moduleID, message string) error {
	state, err := loadModuleState(directory)
	if err != nil {
		return err
	}
	module, exists := state.Modules[moduleID]
	if !exists {
		return errors.New("endpoint module is not installed")
	}
	module.CrashCount++
	module.Error = strings.TrimSpace(message)
	module.Healthy = module.CrashCount < maximumModuleCrashes
	if !module.Healthy && module.PreviousPath != "" && module.PreviousManifest != nil {
		module.ReleaseID, module.Manifest = module.PreviousReleaseID, *module.PreviousManifest
		module.Healthy, module.CrashCount = true, 0
		module.Error = "rolled back after repeated failures"
		module.PreviousPath, module.PreviousReleaseID, module.PreviousManifest = "", "", nil
	}
	state.Modules[moduleID] = module
	return saveModuleState(directory, state)
}

func moduleEnvelopePublisher(envelope []byte) (string, error) {
	var decoded agentmodule.Envelope
	if err := json.Unmarshal(envelope, &decoded); err != nil {
		return "", errors.New("module envelope is invalid")
	}
	var manifest struct {
		PublisherKeyID string `json:"publisher_key_id"`
	}
	if err := json.Unmarshal(decoded.Manifest, &manifest); err != nil || strings.TrimSpace(manifest.PublisherKeyID) == "" {
		return "", errors.New("module publisher is missing")
	}
	return manifest.PublisherKeyID, nil
}

func loadModuleState(directory string) (moduleState, error) {
	state := moduleState{SchemaVersion: 1, Modules: map[string]installedModule{}}
	data, err := os.ReadFile(filepath.Join(directory, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil || state.SchemaVersion != 1 || state.Modules == nil {
		return state, errors.New("endpoint module state is invalid")
	}
	return state, nil
}

func saveModuleState(directory string, state moduleState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeModuleFile(filepath.Join(directory, "state.json"), data, 0o600)
}

func writeModuleFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("commit module file: %w", err)
	}
	return nil
}

func disableAllModules(directory string) error {
	state, err := loadModuleState(directory)
	if err != nil {
		return err
	}
	for id, module := range state.Modules {
		module.Healthy = false
		module.Error = "disabled by server emergency control"
		state.Modules[id] = module
	}
	return saveModuleState(directory, state)
}
