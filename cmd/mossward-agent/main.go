package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"mossward/internal/agentapp"
	"os"
	"os/signal"
	"strings"
)

func main() {
	if err := run(); err != nil {
		slog.Error("Mossward endpoint agent stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("use enroll, run, or diagnose")
	}
	flags := flag.NewFlagSet("mossward-agent "+os.Args[1], flag.ContinueOnError)
	configPath := flags.String("config", os.Getenv("MOSSWARD_AGENT_CONFIG"), "absolute path to endpoint-agent JSON configuration")
	token := flags.String("token", "", "single-use enrollment token")
	tokenStdin := flags.Bool("token-stdin", false, "read the single-use enrollment token from standard input")
	offline := flags.Bool("offline", false, "skip network checks during diagnostics")
	jsonOutput := flags.Bool("json", false, "write diagnostics as JSON")
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
		enrollmentToken, err := readEnrollmentToken(*token, *tokenStdin, os.Stdin)
		if err != nil {
			return err
		}
		return agentapp.Enroll(config, enrollmentToken)
	}
	if os.Args[1] == "diagnose" {
		return runDiagnostics(config, *offline, *jsonOutput)
	}
	if os.Args[1] != "run" {
		return errors.New("use enroll, run, or diagnose")
	}
	app, err := agentapp.New(config)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return app.Run(ctx)
}

func runDiagnostics(config agentapp.Config, offline, jsonOutput bool) error {
	report := agentapp.Diagnose(context.Background(), config, offline)
	if jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			return fmt.Errorf("write diagnostic report: %w", err)
		}
	} else {
		for _, result := range report.Results {
			fmt.Fprintf(os.Stdout, "%-8s %-20s %s\n", strings.ToUpper(string(result.Status)), result.Name, result.Message)
		}
	}
	if !report.Healthy {
		return errors.New("endpoint-agent diagnostics found errors")
	}
	return nil
}

func readEnrollmentToken(argument string, fromStdin bool, input io.Reader) (string, error) {
	if argument != "" && fromStdin {
		return "", errors.New("use either --token or --token-stdin, not both")
	}
	if !fromStdin {
		return argument, nil
	}
	data, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil {
		return "", fmt.Errorf("read enrollment token: %w", err)
	}
	if len(data) > 4096 {
		return "", errors.New("enrollment token input is too large")
	}
	return strings.TrimSpace(string(data)), nil
}
