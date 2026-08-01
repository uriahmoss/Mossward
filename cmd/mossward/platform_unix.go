//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func runPlatform(application func(<-chan string) error) error {
	stop := make(chan string, 1)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		received := <-signals
		stop <- received.String()
	}()
	return application(stop)
}
