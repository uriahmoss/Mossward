package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"mossward/internal/agentmodule"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	manifestPath := flag.String("manifest", "", "verified module manifest")
	packageRoot := flag.String("package-root", "", "verified module package directory")
	flag.Parse()
	if *manifestPath == "" || *packageRoot == "" {
		return errors.New("manifest and package-root are required")
	}
	manifestFile, err := os.Open(*manifestPath)
	if err != nil {
		return err
	}
	defer manifestFile.Close()
	var manifest agentmodule.Manifest
	decoder := json.NewDecoder(manifestFile)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return err
	}
	var request agentmodule.HostRequest
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		return err
	}
	result, err := agentmodule.RunNative(context.Background(), *packageRoot, manifest, request)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
