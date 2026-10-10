//go:build windows

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
	"mossward/internal/workerapp"
)

func manageWorkerService(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: mossward-worker service install --config PATH | start | stop | status | uninstall")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	if args[0] == "install" {
		return installWorkerService(manager, args[1:])
	}
	if len(args) != 1 {
		return errors.New("unexpected worker service arguments")
	}
	if args[0] != "start" && args[0] != "stop" && args[0] != "status" && args[0] != "uninstall" {
		return errors.New("unknown worker service command")
	}
	service, err := manager.OpenService(workerServiceName)
	if err != nil {
		return err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	switch args[0] {
	case "status":
		fmt.Println(status.State)
		return nil
	case "uninstall":
		if status.State != svc.Stopped {
			return errors.New("stop the worker before uninstalling; state and identity files are retained")
		}
		if err := service.Delete(); err != nil {
			return err
		}
		return eventlog.Remove(workerServiceName)
	case "start":
		if err := service.Start(); err != nil {
			return err
		}
		return waitWorkerService(service, svc.Running)
	default:
		if _, err := service.Control(svc.Stop); err != nil {
			return err
		}
		return waitWorkerService(service, svc.Stopped)
	}
}

func installWorkerService(manager *mgr.Mgr, args []string) error {
	flags := flag.NewFlagSet("worker service install", flag.ContinueOnError)
	path := flags.String("config", "", "absolute configuration path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected service installation arguments")
	}
	config, err := workerapp.LoadConfig(*path)
	if err != nil {
		return err
	}
	if err := workerapp.CheckConfig(config); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	service, err := manager.CreateService(workerServiceName, executable, mgr.Config{
		DisplayName: "Mossward Scanner Worker", Description: "Authorized outbound-only Mossward scanner",
		StartType: mgr.StartAutomatic, ServiceStartName: `NT SERVICE\MosswardWorker`, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "--config", *path)
	if err != nil {
		return err
	}
	defer service.Close()
	cleanup := func() { _ = service.Delete(); _ = eventlog.Remove(workerServiceName) }
	if err := eventlog.InstallAsEventCreate(workerServiceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		cleanup()
		return err
	}
	actions := []mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}, {Type: mgr.ServiceRestart, Delay: 30 * time.Second}, {Type: mgr.NoAction}}
	if err := service.SetRecoveryActions(actions, uint32((24 * time.Hour).Seconds())); err != nil {
		cleanup()
		return err
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		cleanup()
		return err
	}
	return nil
}

func waitWorkerService(service *mgr.Service, wanted svc.State) error {
	deadline := time.Now().Add(serviceStopTimeout)
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
	return errors.New("worker service transition timed out")
}
