package privatefs

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
)

// CreateTemp uses exclusive creation with native private permissions.
func CreateTemp(directory, prefix string) (*os.File, error) {
	for attempt := 0; attempt < 10; attempt++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return nil, err
		}
		file, err := Create(filepath.Join(directory, prefix+hex.EncodeToString(random)))
		if os.IsExist(err) {
			continue
		}
		return file, err
	}
	return nil, os.ErrExist
}

func WriteFile(path string, data []byte) error {
	file, err := CreateTemp(filepath.Dir(path), ".mossward-private-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
