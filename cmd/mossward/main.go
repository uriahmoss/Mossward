package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mossward/internal/api"
	"mossward/internal/config"
	"mossward/internal/intelligence"
	"mossward/internal/scanner"
	"mossward/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	repository, err := store.NewSQLiteStore(cfg.DatabaseFile, cfg.LegacyDataFile)
	if err != nil {
		log.Fatal(err)
	}
	defer repository.Close()
	if len(os.Args) > 1 && os.Args[1] == "cve" {
		if err := runCVECommand(repository, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
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

func runCVECommand(repository store.Repository, args []string) error {
	if len(args) == 0 || args[0] != "sync" {
		return errors.New("usage: mossward cve sync [--days 120]")
	}
	flags := flag.NewFlagSet("cve sync", flag.ContinueOnError)
	days := flags.Int("days", 120, "published-date lookback in days (maximum 120)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *days < 1 || *days > 120 {
		return errors.New("--days must be between 1 and 120")
	}
	delay := 6 * time.Second
	apiKey := os.Getenv("MOSSWARD_NVD_API_KEY")
	if apiKey != "" {
		delay = 700 * time.Millisecond
	}
	client := intelligence.NVDClient{APIKey: apiKey, PageDelay: delay}
	until := time.Now().UTC()
	count, err := client.Sync(context.Background(), repository, until.AddDate(0, 0, -*days), until)
	if err != nil {
		return err
	}
	log.Printf("Mossward CVE intelligence updated: %d NVD records processed", count)
	return nil
}
