//go:build !windows

package agentupdate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrRestartRequired = errors.New("endpoint-agent restart required to complete update")

func Activate(executable, candidate, stateDirectory string, transaction Transaction) error {
	if transaction.State != TransactionPrepared {
		return errors.New("only a prepared update transaction can be activated")
	}
	if !filepath.IsAbs(executable) || !filepath.IsAbs(candidate) {
		return errors.New("update executable and candidate paths must be absolute")
	}
	executableInfo, err := os.Lstat(executable)
	if err != nil || !executableInfo.Mode().IsRegular() || executableInfo.Mode().Perm()&0o111 == 0 {
		return errors.New("current endpoint-agent executable is not a regular executable file")
	}
	candidateInfo, err := os.Lstat(candidate)
	if err != nil || !candidateInfo.Mode().IsRegular() || candidateInfo.Size() != transaction.TargetSize {
		return errors.New("staged endpoint-agent candidate does not match the update transaction")
	}

	staged, err := os.CreateTemp(filepath.Dir(executable), ".mossward-agent-activate-")
	if err != nil {
		return fmt.Errorf("create same-filesystem update candidate: %w", err)
	}
	temporary := staged.Name()
	defer os.Remove(temporary)
	if err := staged.Chmod(executableInfo.Mode().Perm()); err != nil {
		staged.Close()
		return err
	}
	if err := copyVerifiedCandidate(staged, candidate, transaction.TargetSize, transaction.TargetSHA256); err != nil {
		staged.Close()
		return err
	}
	if err := staged.Sync(); err != nil {
		staged.Close()
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}

	transaction.State = TransactionAwaitingHealth
	if err := SaveTransaction(stateDirectory, transaction); err != nil {
		return fmt.Errorf("persist pre-activation rollback state: %w", err)
	}
	if err := os.Rename(temporary, executable); err != nil {
		return fmt.Errorf("atomically activate endpoint-agent update: %w", err)
	}
	if err := syncDirectory(filepath.Dir(executable)); err != nil {
		return fmt.Errorf("sync endpoint-agent installation directory: %w", err)
	}
	return ErrRestartRequired
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
