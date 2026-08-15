package agentapp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mossward/internal/model"
)

func nextIntegritySequence(stateDirectory string) (uint64, error) {
	path := filepath.Join(stateDirectory, "integrity-sequence")
	var current uint64
	data, err := os.ReadFile(path)
	if err == nil {
		current, err = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse integrity sequence: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return 0, err
	}
	if current == ^uint64(0) {
		return 0, errors.New("integrity sequence is exhausted")
	}
	next := current + 1
	if err := writePrivateFile(path, []byte(strconv.FormatUint(next, 10)+"\n")); err != nil {
		return 0, err
	}
	return next, nil
}

func collectIntegritySnapshot(config Config, now time.Time) (*model.AgentIntegritySnapshot, error) {
	var issues []error
	executable, err := os.Executable()
	if err != nil {
		issues = append(issues, fmt.Errorf("locate endpoint-agent executable: %w", err))
		executable = "endpoint-agent-unavailable"
	}
	executableHash, hashErr := hashFileStates(executable)
	if hashErr != nil {
		issues = append(issues, fmt.Errorf("hash endpoint-agent executable: %w", hashErr))
	}
	configurationHash, err := hashConfiguration(config)
	if err != nil {
		issues = append(issues, err)
	}
	identityHash, identityErr := hashFileStates(
		filepath.Join(config.StateDirectory, "agent-key.pem"),
		filepath.Join(config.StateDirectory, "agent-cert.pem"),
		filepath.Join(config.StateDirectory, "agent-ca.pem"),
		filepath.Join(config.StateDirectory, "identity.json"),
	)
	if identityErr != nil {
		issues = append(issues, fmt.Errorf("hash endpoint-agent identity files: %w", identityErr))
	}
	return &model.AgentIntegritySnapshot{ExecutableSHA256: executableHash, ConfigurationSHA256: configurationHash, IdentitySHA256: identityHash, ObservedAt: now}, errors.Join(issues...)
}

func hashConfiguration(config Config) (string, error) {
	if config.sourcePath != "" {
		return hashFileStates(config.sourcePath)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("encode endpoint-agent configuration fingerprint: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func hashFileStates(paths ...string) (string, error) {
	hash := sha256.New()
	var issues []error
	for _, path := range paths {
		_, _ = io.WriteString(hash, filepath.Base(path)+"\x00")
		file, err := os.Open(path)
		if err != nil {
			_, _ = io.WriteString(hash, "unreadable\x00")
			issues = append(issues, fmt.Errorf("%s: %w", filepath.Base(path), err))
			continue
		}
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			_, _ = io.WriteString(hash, "read-error\x00")
			issues = append(issues, fmt.Errorf("%s: %s", filepath.Base(path), strings.TrimSpace(fmt.Sprint(copyErr, " ", closeErr))))
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), errors.Join(issues...)
}

func hashFiles(paths ...string) (string, error) {
	hash := sha256.New()
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		_, _ = io.WriteString(hash, filepath.Base(path)+"\x00")
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
