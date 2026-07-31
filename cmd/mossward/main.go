package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mossward/internal/api"
	"mossward/internal/config"
	"mossward/internal/scanner"
	"mossward/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	repository, err := store.NewFileStore(cfg.DataFile)
	if err != nil {
		log.Fatal(err)
	}

	engine, err := scanner.New(cfg, repository)
	if err != nil {
		log.Fatal(err)
	}
	handler := api.New(cfg, repository, engine)
	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("Mossward listening at http://%s", cfg.ListenAddress)
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	engine.Shutdown()
}
