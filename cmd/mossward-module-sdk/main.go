package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"mossward/internal/agentmodule"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("use validate or sign")
	}
	flags := flag.NewFlagSet("mossward-module-sdk "+args[0], flag.ContinueOnError)
	manifestPath := flags.String("manifest", "", "module manifest JSON")
	packagePath := flags.String("package", "", "module package")
	privateKeyPath := flags.String("private-key", "", "unpadded base64 Ed25519 private key file")
	outputPath := flags.String("output", "", "signed envelope output")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	manifest, pkg, err := readInputs(*manifestPath, *packagePath)
	if err != nil {
		return err
	}
	if args[0] == "validate" {
		if manifest.Kind == agentmodule.KindDeclarative {
			return agentmodule.ValidateDeclarativePackage(pkg, manifest)
		}
		return manifest.Validate()
	}
	if args[0] != "sign" || *privateKeyPath == "" || *outputPath == "" {
		return errors.New("sign requires --private-key and --output")
	}
	encodedKey, err := os.ReadFile(*privateKeyPath)
	if err != nil {
		return err
	}
	key, err := base64.RawStdEncoding.DecodeString(string(encodedKey))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("private key file is invalid")
	}
	envelope, err := agentmodule.Sign(manifest, pkg, ed25519.PrivateKey(key))
	if err != nil {
		return err
	}
	return os.WriteFile(*outputPath, envelope, 0o600)
}

func readInputs(manifestPath, packagePath string) (agentmodule.Manifest, []byte, error) {
	var manifest agentmodule.Manifest
	manifestJSON, err := os.ReadFile(manifestPath)
	if err != nil {
		return manifest, nil, err
	}
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return manifest, nil, err
	}
	pkg, err := os.ReadFile(packagePath)
	return manifest, pkg, err
}
