package workerclient

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
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
	if err := os.MkdirAll(directory, privateWorkerDirectoryMode); err != nil {
		return fmt.Errorf("create scanner-worker %s directory: %w", label, err)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("inspect scanner-worker %s directory: %w", label, err)
	}
	if directoryInfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("scanner-worker %s directory permissions are too broad", label)
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("scanner-worker %s permissions are too broad", label)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
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
