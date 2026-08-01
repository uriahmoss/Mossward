package serverbackup

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type RestoreTargets struct {
	DatabaseFile    string
	IdentityKeyFile string
	ACMECacheDir    string
	AgentPKIDir     string
}

type RestoreResult struct {
	Manifest      Manifest
	RecoveryPaths []string
}

type restoreItem struct {
	source      string
	destination string
	isDirectory bool
}

func Restore(archive string, targets RestoreTargets, now time.Time) (RestoreResult, error) {
	if err := validateRestoreTargets(targets); err != nil {
		return RestoreResult{}, err
	}
	directory, manifest, err := extractAndValidate(archive)
	if err != nil {
		return RestoreResult{}, err
	}
	defer os.RemoveAll(directory)
	items := []restoreItem{
		{source: filepath.Join(directory, "database", "mossward.db"), destination: targets.DatabaseFile},
		{source: filepath.Join(directory, "identity", "identity.key"), destination: targets.IdentityKeyFile},
		{source: filepath.Join(directory, "acme"), destination: targets.ACMECacheDir, isDirectory: true},
		{source: filepath.Join(directory, "agent-pki"), destination: targets.AgentPKIDir, isDirectory: true},
	}
	suffix := ".pre-restore-" + now.UTC().Format("20060102T150405.000000000Z")
	recovery := map[string]string{}
	for _, item := range items {
		if item.destination == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(item.destination), 0o750); err != nil {
			return RestoreResult{}, err
		}
		if _, err := os.Stat(item.destination); err == nil {
			recoveryPath := item.destination + suffix
			if err := os.Rename(item.destination, recoveryPath); err != nil {
				rollbackRestore(recovery)
				return RestoreResult{}, fmt.Errorf("preserve current file %q: %w", item.destination, err)
			}
			recovery[item.destination] = recoveryPath
		} else if !os.IsNotExist(err) {
			rollbackRestore(recovery)
			return RestoreResult{}, err
		}
	}
	for _, auxiliary := range []string{targets.DatabaseFile + "-wal", targets.DatabaseFile + "-shm"} {
		if _, err := os.Stat(auxiliary); err == nil {
			recoveryPath := auxiliary + suffix
			if err := os.Rename(auxiliary, recoveryPath); err != nil {
				rollbackRestore(recovery)
				return RestoreResult{}, err
			}
			recovery[auxiliary] = recoveryPath
		}
	}
	for _, item := range items {
		if item.destination == "" {
			continue
		}
		if _, err := os.Stat(item.source); os.IsNotExist(err) && item.isDirectory {
			continue
		}
		if err := copyRestoreItem(item); err != nil {
			for _, created := range items {
				_ = os.RemoveAll(created.destination)
			}
			rollbackRestore(recovery)
			return RestoreResult{}, err
		}
	}
	paths := make([]string, 0, len(recovery))
	for _, path := range recovery {
		paths = append(paths, path)
	}
	return RestoreResult{Manifest: manifest, RecoveryPaths: paths}, nil
}

func validateRestoreTargets(targets RestoreTargets) error {
	paths := []string{targets.DatabaseFile, targets.IdentityKeyFile, targets.ACMECacheDir, targets.AgentPKIDir}
	cleaned := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		for _, existing := range cleaned {
			relative, err := filepath.Rel(existing, absolute)
			if err == nil && (relative == "." || (relative != ".." && !filepath.IsAbs(relative) && !startsWithParent(relative))) {
				return errors.New("restore destinations must not overlap")
			}
			reverse, err := filepath.Rel(absolute, existing)
			if err == nil && (reverse == "." || (reverse != ".." && !filepath.IsAbs(reverse) && !startsWithParent(reverse))) {
				return errors.New("restore destinations must not overlap")
			}
		}
		cleaned = append(cleaned, absolute)
	}
	return nil
}

func startsWithParent(path string) bool {
	return path == ".." || len(path) > 3 && path[:3] == ".."+string(filepath.Separator)
}

func copyRestoreItem(item restoreItem) error {
	if !item.isDirectory {
		return copyFile(item.source, item.destination, 0o600)
	}
	return filepath.WalkDir(item.source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(item.source, path)
		destination := filepath.Join(item.destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o700)
		}
		return copyFile(path, destination, 0o600)
	})
}

func copyFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func rollbackRestore(recovery map[string]string) {
	for destination, recoveryPath := range recovery {
		_ = os.RemoveAll(destination)
		_ = os.Rename(recoveryPath, destination)
	}
}
