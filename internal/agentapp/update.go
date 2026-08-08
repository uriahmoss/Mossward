package agentapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"mossward/internal/agentupdate"
)

func (a *App) applyUpdateOffer(ctx context.Context, envelope json.RawMessage) error {
	if len(envelope) == 0 || !a.config.UpdateEnabled {
		return nil
	}
	manifest, err := agentupdate.Verify(bytes.NewReader(envelope), a.updateKey, a.updateKeyID, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("reject endpoint-agent update offer: %w", err)
	}
	if manifest.OperatingSystem != runtime.GOOS || manifest.Architecture != runtime.GOARCH {
		return errors.New("endpoint-agent update offer targets a different platform")
	}
	if !agentupdate.IsUpgrade(Version, manifest.Version) {
		slog.Info("Endpoint-agent update offer skipped", "running_version", Version, "offered_version", manifest.Version)
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	stateDirectory := a.config.UpdateStateDirectory()
	knownGood, err := agentupdate.PreserveKnownGood(executable, stateDirectory, Version)
	if err != nil {
		return fmt.Errorf("preserve current endpoint agent: %w", err)
	}
	stager, err := agentupdate.NewStager(filepath.Join(stateDirectory, "staging"), a.client)
	if err != nil {
		return err
	}
	candidate, err := stager.Stage(ctx, manifest)
	if err != nil {
		return err
	}
	transaction, err := agentupdate.NewTransaction(knownGood, manifest, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := agentupdate.SaveTransaction(stateDirectory, transaction); err != nil {
		return err
	}
	slog.Info("Activating verified endpoint-agent update", "current_version", Version, "target_version", manifest.Version)
	return agentupdate.Activate(executable, candidate, stateDirectory, transaction)
}
