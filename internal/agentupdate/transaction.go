package agentupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	transactionSchemaVersion = 1
	maximumTransactionBytes  = 16 << 10
	transactionFileName      = "transaction.json"
)

type TransactionState string

const (
	TransactionPrepared       TransactionState = "prepared"
	TransactionAwaitingHealth TransactionState = "awaiting_health"
	TransactionCommitted      TransactionState = "committed"
	TransactionRollback       TransactionState = "rollback_required"
)

type KnownGood struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	File    string `json:"file"`
}

type Transaction struct {
	SchemaVersion  int              `json:"schema_version"`
	State          TransactionState `json:"state"`
	Previous       KnownGood        `json:"previous"`
	TargetVersion  string           `json:"target_version"`
	TargetSHA256   string           `json:"target_sha256"`
	TargetSize     int64            `json:"target_size"`
	StartedAt      time.Time        `json:"started_at"`
	HealthDeadline time.Time        `json:"health_deadline"`
}

func PreserveKnownGood(executable, directory, version string) (KnownGood, error) {
	if !filepath.IsAbs(executable) || !filepath.IsAbs(directory) || !versionPattern.MatchString(version) {
		return KnownGood{}, errors.New("known-good executable, directory, or version is invalid")
	}
	if err := protectUpdateDirectory(directory); err != nil {
		return KnownGood{}, err
	}
	source, err := os.Open(executable)
	if err != nil {
		return KnownGood{}, fmt.Errorf("open known-good executable: %w", err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumArtifactBytes {
		return KnownGood{}, errors.New("known-good executable is not a bounded regular file")
	}
	fileName := "known-good-" + version
	finalPath := filepath.Join(directory, fileName)
	if _, err := os.Lstat(finalPath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return KnownGood{}, errors.New("known-good version already exists")
		}
		return KnownGood{}, err
	}
	temporary, err := os.CreateTemp(directory, ".mossward-known-good-")
	if err != nil {
		return KnownGood{}, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o500); err != nil {
		temporary.Close()
		return KnownGood{}, err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(source, maximumArtifactBytes+1))
	if copyErr != nil || written != info.Size() {
		temporary.Close()
		return KnownGood{}, errors.New("copy known-good executable failed or changed during backup")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return KnownGood{}, err
	}
	if err := temporary.Close(); err != nil {
		return KnownGood{}, err
	}
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		return KnownGood{}, fmt.Errorf("preserve known-good executable: %w", err)
	}
	return KnownGood{Version: version, SHA256: hex.EncodeToString(hash.Sum(nil)), Size: written, File: fileName}, nil
}

func NewTransaction(previous KnownGood, manifest Manifest, now time.Time) (Transaction, error) {
	transaction := Transaction{SchemaVersion: transactionSchemaVersion, State: TransactionPrepared, Previous: previous,
		TargetVersion: manifest.Version, TargetSHA256: manifest.ArtifactSHA256, TargetSize: manifest.ArtifactSize, StartedAt: now.UTC(),
		HealthDeadline: now.UTC().Add(time.Duration(manifest.HealthTimeoutSeconds) * time.Second)}
	return transaction, transaction.Validate()
}

func (t Transaction) Validate() error {
	validState := t.State == TransactionPrepared || t.State == TransactionAwaitingHealth || t.State == TransactionCommitted || t.State == TransactionRollback
	previousDigest, previousErr := hex.DecodeString(t.Previous.SHA256)
	targetDigest, targetErr := hex.DecodeString(t.TargetSHA256)
	if t.SchemaVersion != transactionSchemaVersion || !validState || !versionPattern.MatchString(t.Previous.Version) ||
		!versionPattern.MatchString(t.TargetVersion) || filepath.Base(t.Previous.File) != t.Previous.File ||
		previousErr != nil || len(previousDigest) != 32 || targetErr != nil || len(targetDigest) != 32 ||
		t.Previous.Size < 1 || t.Previous.Size > maximumArtifactBytes || t.TargetSize < 1 || t.TargetSize > maximumArtifactBytes || !t.HealthDeadline.After(t.StartedAt) ||
		t.HealthDeadline.Sub(t.StartedAt) > maximumHealthTimeout*time.Second {
		return errors.New("update transaction is invalid")
	}
	return nil
}

func (t Transaction) RequiresRollback(now time.Time) bool {
	return t.State == TransactionRollback || (t.State == TransactionAwaitingHealth && !now.Before(t.HealthDeadline))
}

func SaveTransaction(directory string, transaction Transaction) error {
	if err := transaction.Validate(); err != nil {
		return err
	}
	if err := protectUpdateDirectory(directory); err != nil {
		return err
	}
	data, err := json.Marshal(transaction)
	if err != nil {
		return err
	}
	return writePrivateFile(filepath.Join(directory, transactionFileName), data)
}

func LoadTransaction(directory string) (Transaction, error) {
	var transaction Transaction
	file, err := os.Open(filepath.Join(directory, transactionFileName))
	if err != nil {
		return transaction, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maximumTransactionBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&transaction); err != nil {
		return transaction, fmt.Errorf("decode update transaction: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return transaction, errors.New("update transaction contains trailing data")
	}
	return transaction, transaction.Validate()
}

func protectUpdateDirectory(directory string) error {
	if !filepath.IsAbs(directory) {
		return errors.New("update state directory must be absolute")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create update state directory: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(directory, 0o700); err != nil {
			return fmt.Errorf("protect update state directory: %w", err)
		}
	}
	return nil
}

func writePrivateFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".mossward-transaction-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
