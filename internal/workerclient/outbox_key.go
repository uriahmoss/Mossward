package workerclient

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
)

func loadOrCreateOutboxKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != outboxKeyBytes {
			return nil, errors.New("scanner-worker outbox key has an invalid length")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read scanner-worker outbox key: %w", err)
	}
	key = make([]byte, outboxKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate scanner-worker outbox key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateWorkerFileMode)
	if err != nil {
		return nil, fmt.Errorf("create scanner-worker outbox key: %w", err)
	}
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write scanner-worker outbox key: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("sync scanner-worker outbox key: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close scanner-worker outbox key: %w", err)
	}
	return key, nil
}
