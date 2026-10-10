//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"mossward/internal/workerapp"
)

const workerServiceName = "MosswardWorker"
const serviceStopTimeout = 30 * time.Second

func runWorkerPlatform(config workerapp.Config) error {
	interactive, err := svc.IsAnInteractiveSession()
	if err != nil {
		return err
	}
	if interactive {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return runWorker(ctx, config)
	}
	return svc.Run(workerServiceName, &workerService{config: config})
}

type workerService struct{ config workerapp.Config }

func (service *workerService) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	log, err := eventlog.Open(workerServiceName)
	if err != nil {
		return false, 1
	}
	defer log.Close()
	slog.SetDefault(slog.New(&workerEventLog{log: log}))
	if err := workerapp.CheckConfig(service.config); err != nil {
		_ = log.Error(1, "Scanner-worker identity/configuration validation failed")
		return false, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runWorker(ctx, service.config) }()
	statuses <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	_ = log.Info(1, "Mossward scanner worker started")
	for {
		select {
		case err := <-done:
			return serviceResult(log, err)
		case request, open := <-requests:
			if !open {
				cancel()
				return serviceResult(log, <-done)
			}
			if request.Cmd == svc.Interrogate {
				statuses <- request.CurrentStatus
				continue
			}
			if request.Cmd != svc.Stop && request.Cmd != svc.Shutdown {
				continue
			}
			statuses <- svc.Status{State: svc.StopPending}
			cancel()
			select {
			case err := <-done:
				return serviceResult(log, err)
			case <-time.After(serviceStopTimeout):
				return serviceResult(log, errors.New("worker shutdown timed out"))
			}
		}
	}
}

func serviceResult(log *eventlog.Log, err error) (bool, uint32) {
	if err != nil {
		slog.Error("Scanner-worker service failed", "error", err)
		_ = log.Error(1, fmt.Sprint("Mossward scanner worker failed: ", err))
		return false, 1
	}
	_ = log.Info(1, "Mossward scanner worker stopped; queued evidence retained")
	return false, 0
}
