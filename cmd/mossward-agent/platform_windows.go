//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"mossward/internal/agentapp"
)

const (
	agentWindowsServiceName    = "MosswardAgent"
	agentWindowsServiceTimeout = 30 * time.Second
)

func runAgentPlatform(config agentapp.Config) error {
	interactive, err := svc.IsAnInteractiveSession()
	if err != nil {
		return fmt.Errorf("detect Windows service session: %w", err)
	}
	if interactive {
		return runInteractiveAgent(config)
	}
	log, err := eventlog.Open(agentWindowsServiceName)
	if err != nil {
		return fmt.Errorf("open Mossward Agent event log: %w", err)
	}
	defer log.Close()
	slog.SetDefault(slog.New(newAgentWindowsEventLogHandler(log)))
	return svc.Run(agentWindowsServiceName, &agentWindowsService{config: config})
}

func runInteractiveAgent(config agentapp.Config) error {
	app, err := agentapp.New(config)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return app.Run(ctx)
}

type agentWindowsService struct {
	config agentapp.Config
}

func (service *agentWindowsService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	app, err := agentapp.New(service.config)
	if err != nil {
		slog.Error("Mossward endpoint agent initialization failed", "error", err)
		return false, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				slog.Error("Mossward endpoint agent service failed", "error", err)
				return false, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				if err := <-done; err != nil {
					return false, 1
				}
				return false, 0
			}
		}
	}
}

func manageAgentService(args []string) error {
	if len(args) == 0 {
		return serviceUsageError()
	}
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to Windows Service Control Manager: %w", err)
	}
	defer manager.Disconnect()
	switch strings.ToLower(args[0]) {
	case "install":
		return installAgentWindowsService(manager, args[1:])
	case "uninstall":
		return uninstallAgentWindowsService(manager)
	case "start":
		return changeAgentWindowsService(manager, true)
	case "stop":
		return changeAgentWindowsService(manager, false)
	case "status":
		return printAgentWindowsServiceStatus(manager)
	default:
		return serviceUsageError()
	}
}

func serviceUsageError() error {
	return errors.New("usage: mossward-agent service install --config PATH | uninstall | start | stop | status")
}

func installAgentWindowsService(manager *mgr.Mgr, args []string) error {
	flags := flag.NewFlagSet("mossward-agent service install", flag.ContinueOnError)
	configPath := flags.String("config", "", "absolute endpoint-agent configuration path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || !filepath.IsAbs(*configPath) || flags.NArg() != 0 {
		return serviceUsageError()
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve endpoint-agent executable: %w", err)
	}
	service, err := manager.CreateService(agentWindowsServiceName, executable, mgr.Config{
		DisplayName: "Mossward Endpoint Detection Agent", Description: "Mossward outbound endpoint detection and evidence agent",
		StartType: mgr.StartAutomatic, ServiceStartName: `NT SERVICE\MosswardAgent`, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "run", "--config", *configPath)
	if err != nil {
		return fmt.Errorf("install Mossward Agent Windows service: %w", err)
	}
	defer service.Close()
	cleanup := func() {
		_ = service.Delete()
		_ = eventlog.Remove(agentWindowsServiceName)
	}
	if err := eventlog.InstallAsEventCreate(agentWindowsServiceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		cleanup()
		return fmt.Errorf("install Mossward Agent event log source: %w", err)
	}
	actions := []mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second}, {Type: mgr.NoAction}}
	if err := service.SetRecoveryActions(actions, uint32((24 * time.Hour).Seconds())); err != nil {
		cleanup()
		return fmt.Errorf("configure Mossward Agent service recovery: %w", err)
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		cleanup()
		return err
	}
	return nil
}

func uninstallAgentWindowsService(manager *mgr.Mgr) error {
	service, err := manager.OpenService(agentWindowsServiceName)
	if err != nil {
		return err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped {
		return errors.New("stop the Mossward Agent service before uninstalling it")
	}
	if err := service.Delete(); err != nil {
		return err
	}
	return eventlog.Remove(agentWindowsServiceName)
}

func changeAgentWindowsService(manager *mgr.Mgr, start bool) error {
	service, err := manager.OpenService(agentWindowsServiceName)
	if err != nil {
		return err
	}
	defer service.Close()
	wanted := svc.Running
	if start {
		if err := service.Start(); err != nil {
			return err
		}
	} else {
		wanted = svc.Stopped
		if _, err := service.Control(svc.Stop); err != nil {
			return err
		}
	}
	return waitForAgentWindowsService(service, wanted)
}

func printAgentWindowsServiceStatus(manager *mgr.Mgr) error {
	service, err := manager.OpenService(agentWindowsServiceName)
	if err != nil {
		return err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	fmt.Println(agentWindowsServiceState(status.State))
	return nil
}

func waitForAgentWindowsService(service *mgr.Service, wanted svc.State) error {
	deadline := time.Now().Add(agentWindowsServiceTimeout)
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == wanted {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("Windows service did not reach %s within %s", agentWindowsServiceState(wanted), agentWindowsServiceTimeout)
}

func agentWindowsServiceState(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start pending"
	case svc.StopPending:
		return "stop pending"
	case svc.Running:
		return "running"
	default:
		return fmt.Sprintf("state %d", state)
	}
}
