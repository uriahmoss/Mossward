package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"mossward/internal/postgresverify"
)

func main() {
	tools := flag.String("tools-dir", "", "Directory containing native PostgreSQL binaries")
	major := flag.Int("expected-major", 0, "Expected PostgreSQL major; zero accepts supported installed versions")
	flag.Parse()
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, 20*time.Minute)
	defer cancel()
	if err := postgresverify.Run(ctx, *tools, *major); err != nil {
		slog.Error("PostgreSQL verification failed", "error", err)
		os.Exit(1)
	}
	slog.Info("PostgreSQL verification passed")
}
