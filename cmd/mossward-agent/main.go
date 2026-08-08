package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"mossward/internal/agentapp"
	"os"
	"os/signal"
)

func main() {
	if err := run(); err != nil {
		slog.Error("Mossward endpoint agent stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("use enroll or run")
	}
	flags := flag.NewFlagSet("mossward-agent "+os.Args[1], flag.ContinueOnError)
	configPath := flags.String("config", os.Getenv("MOSSWARD_AGENT_CONFIG"), "absolute path to endpoint-agent JSON configuration")
	token := flags.String("token", "", "single-use enrollment token")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("endpoint-agent configuration is required")
	}
	config, err := agentapp.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if os.Args[1] == "enroll" {
		return agentapp.Enroll(config, *token)
	}
	if os.Args[1] != "run" {
		return errors.New("use enroll or run")
	}
	app, err := agentapp.New(config)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return app.Run(ctx)
}
