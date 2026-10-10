//go:build !windows

package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"mossward/internal/workerapp"
)

func runWorkerPlatform(config workerapp.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runWorker(ctx, config)
}

func manageWorkerService([]string) error {
	return errors.New("worker service commands are Windows-only; use the supplied systemd unit on Linux")
}
