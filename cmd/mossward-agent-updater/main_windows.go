//go:build windows

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"mossward/internal/agentupdate"
)

const (
	serviceName        = "MosswardAgent"
	serviceWait        = 30 * time.Second
	healthPollInterval = time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("mossward-agent-updater", flag.ContinueOnError)
	executable := flags.String("executable", "", "absolute installed endpoint-agent executable")
	stateDirectory := flags.String("state-directory", "", "absolute endpoint-agent update state directory")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*executable) || !filepath.IsAbs(*stateDirectory) {
		return errors.New("usage: mossward-agent-updater --executable PATH --state-directory PATH")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	transaction, err := agentupdate.LoadTransaction(*stateDirectory)
	if err != nil {
		return err
	}
	if transaction.RequiresRollback(time.Now().UTC()) {
		return rollback(service, *executable, *stateDirectory, errors.New("update transaction requires rollback"))
	}
	if err := agentupdate.VerifyArtifact(*executable, transaction.TargetSize, transaction.TargetSHA256); err != nil {
		if stopErr := stopService(service); stopErr != nil {
			return stopErr
		}
		if err := agentupdate.ApplyPendingWindowsUpdate(*executable, *stateDirectory); err != nil {
			return err
		}
	}
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		if err := service.Start(); err != nil {
			return rollback(service, *executable, *stateDirectory, err)
		}
	}
	return monitorHealth(service, *executable, *stateDirectory)
}

func monitorHealth(service *mgr.Service, executable, stateDirectory string) error {
	for {
		transaction, err := agentupdate.LoadTransaction(stateDirectory)
		if err != nil {
			return err
		}
		if transaction.State == agentupdate.TransactionCommitted {
			return nil
		}
		if transaction.RequiresRollback(time.Now().UTC()) {
			return rollback(service, executable, stateDirectory, errors.New("updated agent missed its health deadline"))
		}
		time.Sleep(healthPollInterval)
	}
}

func rollback(service *mgr.Service, executable, stateDirectory string, updateErr error) error {
	if err := stopService(service); err != nil {
		return fmt.Errorf("update failed (%v) and service could not stop for rollback: %w", updateErr, err)
	}
	if err := agentupdate.RollbackWindowsUpdate(executable, stateDirectory); err != nil {
		return fmt.Errorf("update failed (%v) and rollback failed: %w", updateErr, err)
	}
	if err := service.Start(); err != nil {
		return fmt.Errorf("rollback completed but known-good service could not start: %w", err)
	}
	return fmt.Errorf("Windows endpoint-agent update rolled back: %w", updateErr)
}

func stopService(service *mgr.Service) error {
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	if _, err := service.Control(svc.Stop); err != nil {
		return err
	}
	deadline := time.Now().Add(serviceWait)
	for time.Now().Before(deadline) {
		status, err = service.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("Mossward Agent service did not stop within 30 seconds")
}
