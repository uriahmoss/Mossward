//go:build !windows

// Package privatefs protects private application files using native permissions.
package privatefs

import (
	"errors"
	"os"
)

func Restrict(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("private path must not be a symbolic link")
	}
	mode := os.FileMode(0o600)
	if info.IsDir() {
		mode = 0o700
	}
	return os.Chmod(path, mode)
}

func Check(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("private path grants group or other access")
	}
	return nil
}

func Create(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
}

// RequirePrivateDirectory protects Windows sidecar inheritance. Unix file modes
// are set independently and do not require changing shared parent directories.
func RequirePrivateDirectory(string) error { return nil }

func MkdirAll(path string) error { return os.MkdirAll(path, 0o700) }
