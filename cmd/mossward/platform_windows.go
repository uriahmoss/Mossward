//go:build windows

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	windowsServiceName    = "Mossward"
	windowsServiceTimeout = 30 * time.Second
)

func runPlatform(application func(<-chan string) error) error {
	if len(os.Args) > 1 && os.Args[1] == "service" {
		return manageWindowsService(os.Args[2:])
	}
	interactive, err := svc.IsAnInteractiveSession()
	if err != nil {
		return fmt.Errorf("detect Windows service session: %w", err)
	}
	if !interactive {
		log, err := eventlog.Open(windowsServiceName)
		if err != nil {
			return fmt.Errorf("open Mossward Windows event log: %w", err)
		}
		defer log.Close()
		slog.SetDefault(slog.New(newWindowsEventLogHandler(log)))
		return svc.Run(windowsServiceName, &windowsService{application: application})
	}
	stop := make(chan string, 1)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	defer signal.Stop(signals)
	go func() {
		<-signals
		stop <- "console interrupt"
	}()
	return application(stop)
}

type windowsService struct {
	application func(<-chan string) error
}

func (service *windowsService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	stop := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- service.application(stop) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				return false, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				stop <- "Windows Service Control Manager"
				if err := <-done; err != nil {
					return false, 1
				}
				return false, 0
			}
		}
	}
}

func manageWindowsService(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: mossward service install|uninstall|start|stop|status")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to Windows Service Control Manager: %w", err)
	}
	defer manager.Disconnect()
	switch strings.ToLower(args[0]) {
	case "install":
		return installWindowsService(manager)
	case "uninstall":
		return uninstallWindowsService(manager)
	case "start":
		return startWindowsService(manager)
	case "stop":
		return stopWindowsService(manager)
	case "status":
		return printWindowsServiceStatus(manager)
	default:
		return errors.New("usage: mossward service install|uninstall|start|stop|status")
	}
}

func installWindowsService(manager *mgr.Mgr) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve Mossward executable: %w", err)
	}
	service, err := manager.CreateService(windowsServiceName, executable, mgr.Config{
		DisplayName: "Mossward Security Detection Server", Description: "Mossward vulnerability detection and endpoint coordination server",
		StartType: mgr.StartAutomatic, ServiceStartName: `NT SERVICE\Mossward`, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "service-run")
	if err != nil {
		return fmt.Errorf("install Mossward Windows service: %w", err)
	}
	defer service.Close()
	cleanup := func() {
		_ = service.Delete()
		_ = eventlog.Remove(windowsServiceName)
	}
	if err := eventlog.InstallAsEventCreate(windowsServiceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		cleanup()
		return fmt.Errorf("install Mossward event log source: %w", err)
	}
	actions := []mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second}, {Type: mgr.NoAction}}
	if err := service.SetRecoveryActions(actions, uint32((24 * time.Hour).Seconds())); err != nil {
		cleanup()
		return fmt.Errorf("configure Mossward service recovery: %w", err)
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		cleanup()
		return err
	}
	return nil
}

func uninstallWindowsService(manager *mgr.Mgr) error {
	service, err := manager.OpenService(windowsServiceName)
	if err != nil {
		return fmt.Errorf("open Mossward Windows service: %w", err)
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped {
		return errors.New("stop the Mossward service before uninstalling it")
	}
	if err := service.Delete(); err != nil {
		return err
	}
	return eventlog.Remove(windowsServiceName)
}

func startWindowsService(manager *mgr.Mgr) error {
	service, err := manager.OpenService(windowsServiceName)
	if err != nil {
		return err
	}
	defer service.Close()
	if err := service.Start(); err != nil {
		return err
	}
	return waitWindowsService(service, svc.Running)
}

func stopWindowsService(manager *mgr.Mgr) error {
	service, err := manager.OpenService(windowsServiceName)
	if err != nil {
		return err
	}
	defer service.Close()
	if _, err := service.Control(svc.Stop); err != nil {
		return err
	}
	return waitWindowsService(service, svc.Stopped)
}

func printWindowsServiceStatus(manager *mgr.Mgr) error {
	service, err := manager.OpenService(windowsServiceName)
	if err != nil {
		return err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	fmt.Println(windowsServiceState(status.State))
	return nil
}

func waitWindowsService(service *mgr.Service, wanted svc.State) error {
	deadline := time.Now().Add(windowsServiceTimeout)
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
	return fmt.Errorf("Windows service did not reach %s within %s", windowsServiceState(wanted), windowsServiceTimeout)
}

func windowsServiceState(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start pending"
	case svc.StopPending:
		return "stop pending"
	case svc.Running:
		return "running"
	case svc.PausePending:
		return "pause pending"
	case svc.Paused:
		return "paused"
	case svc.ContinuePending:
		return "continue pending"
	default:
		return fmt.Sprintf("unknown (%d)", state)
	}
}
