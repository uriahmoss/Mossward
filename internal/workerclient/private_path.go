package workerclient

import (
	"errors"
	"fmt"
	"mossward/internal/privatefs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	privateWorkerFileMode      = 0o600
	privateWorkerDirectoryMode = 0o700
)

func preparePrivateWorkerPath(path, label string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("scanner-worker %s path is required", label)
	}
	directory := filepath.Dir(path)
	if err := privatefs.MkdirAll(directory); err != nil {
		return fmt.Errorf("create scanner-worker %s directory: %w", label, err)
	}
	if err := privatefs.Check(directory); err != nil {
		return fmt.Errorf("scanner-worker %s directory permissions are too broad: %w", label, err)
	}
	if err := privatefs.Check(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect scanner-worker %s: %w", label, err)
	}
	return nil
}

func workerSQLiteDSN(path string) (string, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve scanner-worker database path: %w", err)
	}
	slashPath := filepath.ToSlash(absolutePath)
	if filepath.VolumeName(absolutePath) != "" && !strings.HasPrefix(slashPath, "/") {
		slashPath = "/" + slashPath
	}
	return (&url.URL{Scheme: "file", Path: slashPath,
		RawQuery: "_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)"}).String(), nil
}
