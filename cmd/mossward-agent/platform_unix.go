//go:build !windows

package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"mossward/internal/agentapp"
)

func runAgentPlatform(config agentapp.Config) error {
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
