//go:build !windows

package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mossward/internal/agentapp"
	"mossward/internal/agentupdate"
)

func runAgentPlatform(config agentapp.Config) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if err := agentupdate.Recover(executable, config.UpdateStateDirectory(), time.Now().UTC()); err != nil {
		return err
	}
	app, err := agentapp.New(config)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.Run(ctx)
}

func manageAgentService([]string) error {
	return errors.New("native service management is available only on Windows")
}
