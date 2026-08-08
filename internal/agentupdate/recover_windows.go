//go:build windows

package agentupdate

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

const windowsUpdaterName = "mossward-agent-updater.exe"

func Recover(executable, stateDirectory string, now time.Time) error {
	transaction, err := LoadTransaction(stateDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if transaction.State == TransactionCommitted || transaction.State == TransactionRolledBack || transaction.State == TransactionPrepared {
		return nil
	}
	if transaction.State == TransactionAwaitingHealth && !transaction.RequiresRollback(now) {
		if _, err := os.Lstat(pendingWindowsExecutable(executable)); errors.Is(err, os.ErrNotExist) {
			return VerifyArtifact(executable, transaction.TargetSize, transaction.TargetSHA256)
		}
	}
	if err := launchWindowsUpdater(executable, stateDirectory); err != nil {
		return err
	}
	return ErrRestartRequired
}

func launchWindowsUpdater(executable, stateDirectory string) error {
	updater := filepath.Join(filepath.Dir(executable), windowsUpdaterName)
	info, err := os.Lstat(updater)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("signed Windows endpoint-agent updater is unavailable")
	}
	command := exec.Command(updater, "--executable", executable, "--state-directory", stateDirectory)
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS, HideWindow: true}
	if err := command.Start(); err != nil {
		return fmt.Errorf("launch Windows endpoint-agent updater: %w", err)
	}
	return command.Process.Release()
}
