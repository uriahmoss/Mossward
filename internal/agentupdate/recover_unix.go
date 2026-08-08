//go:build !windows

package agentupdate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func Recover(executable, stateDirectory string, now time.Time) error {
	transaction, err := LoadTransaction(stateDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !transaction.RequiresRollback(now) {
		return nil
	}
	knownGoodPath := filepath.Join(stateDirectory, transaction.Previous.File)
	executableInfo, err := os.Lstat(executable)
	if err != nil || !executableInfo.Mode().IsRegular() {
		return errors.New("installed endpoint-agent executable cannot be recovered")
	}
	staged, err := os.CreateTemp(filepath.Dir(executable), ".mossward-agent-rollback-")
	if err != nil {
		return err
	}
	temporary := staged.Name()
	defer os.Remove(temporary)
	if err := staged.Chmod(executableInfo.Mode().Perm()); err != nil {
		staged.Close()
		return err
	}
	if err := copyVerifiedCandidate(staged, knownGoodPath, transaction.Previous.Size, transaction.Previous.SHA256); err != nil {
		staged.Close()
		return fmt.Errorf("verify known-good endpoint agent: %w", err)
	}
	if err := staged.Sync(); err != nil {
		staged.Close()
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	transaction.State = TransactionRollback
	if err := SaveTransaction(stateDirectory, transaction); err != nil {
		return err
	}
	if err := os.Rename(temporary, executable); err != nil {
		return fmt.Errorf("restore known-good endpoint agent: %w", err)
	}
	if err := syncDirectory(filepath.Dir(executable)); err != nil {
		return err
	}
	transaction.State = TransactionRolledBack
	if err := SaveTransaction(stateDirectory, transaction); err != nil {
		return fmt.Errorf("record completed endpoint-agent rollback: %w", err)
	}
	return ErrRestartRequired
}
