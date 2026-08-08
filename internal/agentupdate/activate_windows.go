//go:build windows

package agentupdate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

var ErrRestartRequired = errors.New("endpoint-agent restart required to complete update")
var ErrExternalHelperRequired = errors.New("Windows stopped-service update helper required")

func Activate(executable, candidate, stateDirectory string, transaction Transaction) error {
	if transaction.State != TransactionPrepared || !filepath.IsAbs(executable) || !filepath.IsAbs(candidate) {
		return errors.New("Windows update activation request is invalid")
	}
	info, err := os.Lstat(candidate)
	if err != nil || !info.Mode().IsRegular() || info.Size() != transaction.TargetSize {
		return errors.New("staged Windows endpoint-agent candidate does not match the update transaction")
	}
	pending := pendingWindowsExecutable(executable)
	if _, err := os.Lstat(pending); !errors.Is(err, os.ErrNotExist) {
		return errors.New("a Windows endpoint-agent replacement is already pending")
	}
	file, err := os.CreateTemp(filepath.Dir(executable), ".mossward-agent-pending-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o700); err != nil {
		file.Close()
		return err
	}
	if err := copyVerifiedCandidate(file, candidate, transaction.TargetSize, transaction.TargetSHA256); err != nil {
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
	transaction.State = TransactionAwaitingHealth
	if err := SaveTransaction(stateDirectory, transaction); err != nil {
		return fmt.Errorf("persist Windows rollback state: %w", err)
	}
	if err := os.Rename(temporary, pending); err != nil {
		return fmt.Errorf("stage Windows replacement beside executable: %w", err)
	}
	if err := launchWindowsUpdater(executable, stateDirectory); err != nil {
		return err
	}
	return ErrRestartRequired
}

func ApplyPendingWindowsUpdate(executable, stateDirectory string) error {
	transaction, err := LoadTransaction(stateDirectory)
	if err != nil {
		return err
	}
	if transaction.State != TransactionAwaitingHealth {
		return errors.New("Windows update transaction is not awaiting activation")
	}
	pending := pendingWindowsExecutable(executable)
	info, err := os.Lstat(pending)
	if err != nil || !info.Mode().IsRegular() || info.Size() != transaction.TargetSize {
		return errors.New("pending Windows executable does not match the update transaction")
	}
	from, err := windows.UTF16PtrFromString(pending)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("replace stopped Windows endpoint agent: %w", err)
	}
	return nil
}

func RollbackWindowsUpdate(executable, stateDirectory string) error {
	transaction, err := LoadTransaction(stateDirectory)
	if err != nil {
		return err
	}
	knownGood := filepath.Join(stateDirectory, transaction.Previous.File)
	file, err := os.CreateTemp(filepath.Dir(executable), ".mossward-agent-rollback-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o700); err != nil {
		file.Close()
		return err
	}
	if err := copyVerifiedCandidate(file, knownGood, transaction.Previous.Size, transaction.Previous.SHA256); err != nil {
		file.Close()
		return fmt.Errorf("verify known-good Windows endpoint agent: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	transaction.State = TransactionRollback
	if err := SaveTransaction(stateDirectory, transaction); err != nil {
		return err
	}
	from, _ := windows.UTF16PtrFromString(temporary)
	to, _ := windows.UTF16PtrFromString(executable)
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("restore known-good Windows endpoint agent: %w", err)
	}
	transaction.State = TransactionRolledBack
	return SaveTransaction(stateDirectory, transaction)
}

func pendingWindowsExecutable(executable string) string {
	return executable + ".pending"
}
